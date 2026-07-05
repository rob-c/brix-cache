# K8s Test Lab — Sub-project #1: Auth-Authority Plane — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **No git commands** are run in this project: every "Checkpoint (no git)" step is a verification gate, not a commit.

**Goal:** Stand up the x509 (CA/CRL/VOMS), WLCG token (JWKS issuer), and Kerberos (KDC) authorities as dedicated in-cluster **site services** that the fleet consumes over the network — CRLs and JWKS pulled over HTTP into the servers' file paths exactly as a production grid site does.

**Architecture:** A one-shot **bootstrap Job** runs the repo's existing provisioning (`pki_helpers.blitz_test_pki`, `utils/make_proxy.py`, `utils/make_crl.py`, `utils/make_token.py`, `kdc_helpers.py`) and publishes private material to Secrets and public material to ConfigMaps. Long-running **authority Deployments** serve the public material over HTTP (CA bundle + CRL distribution point; JWKS endpoint) or over their native protocol (KDC on 88). Consuming servers (built in #3) mount the CA bundle and run a **fetch sidecar** that refreshes the CRL / JWKS file the `brix_*` directive reads. Depends on Sub-project #0 (`brix-common`, `xrd-lab`, umbrella).

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, Python 3 (existing provisioning scripts), MIT krb5, a static HTTP server (nginx) for CA/CRL/JWKS distribution.

**Spec:** `docs/superpowers/specs/2026-07-04-k8s-test-lab-design.md` §4.2. **Dependency:** Sub-project #0 must be complete (this plan consumes `charts/brix-common` and the `xrd-lab deploy`/profile convention).

## Global Constraints

- Inherits every constraint from the #0 plan's Global Constraints (pinned k8s version, no external registry / `pullPolicy: Never`, `brix-<profile>` namespaces + PodSecurity labels, `set -euo pipefail` + shellcheck-clean shell, cross-cutting policy only in `brix-common`).
- **The bootstrap Job is the sole producer of auth material.** Authorities and fleet servers are pure consumers of its Secrets/ConfigMaps. A redeploy re-runs the Job idempotently.
- **Servers consume dynamic material by file, refreshed over HTTP.** `brix_crl`/`brix_webdav_crl` and `brix_token_jwks` point at a file on an `emptyDir`; a sidecar curls the authority HTTP endpoint into that file on an interval. Never bake CRL/JWKS into an image.
- **Realm/issuer/audience constants are fixed and single-sourced** in values: realm `NGINX.TEST`, service principal `xrootd/<svc-dns>@NGINX.TEST`, token issuer `https://test.example.com`, audience `nginx-xrootd` (these match `tests/kdc_helpers.py` and `tests/configs/nginx_shared.conf`).

## Provisioning entry points (verified in-repo)

| Material | Producer (repo path) | Output paths (under a work dir) |
|---|---|---|
| CA, host cert, user cert, vomsdir | `tests/pki_helpers.py::blitz_test_pki()` (reads `PKI_DIR`) | `ca/ca.pem`, `ca/<hash>.0`, `server/hostcert.pem`+`server/hostkey.pem`, `user/usercert.pem`+`user/userkey.pem`, `vomsdir/` |
| Proxy cert | `utils/make_proxy.py <pki_dir>` | `user/userproxy.pem` |
| CRL | `utils/make_crl.py` (via `pki_helpers`) | `ca/test-user.crl.pem` |
| Token signing key + JWKS | `utils/make_token.py init <dir>` then sign | `<dir>/signing_key.pem`, `<dir>/jwks.json` |
| KDC realm + keytab | `tests/kdc_helpers.py up` | `krb5/krb5.conf`, `krb5/brix.keytab`, KDC db |

---

## File Structure

```
k8s-tests/
├── charts/auth-authority/
│   ├── Chart.yaml                              # dependency: brix-common
│   ├── values.yaml
│   ├── templates/
│   │   ├── _authority.tpl                       # shared authority Deployment+Service macro (Task 2)
│   │   ├── bootstrap-job.yaml                   # runs provisioning, writes Secrets/ConfigMaps (Task 3)
│   │   ├── bootstrap-rbac.yaml                  # ServiceAccount+Role allowing the Job to write Secrets/ConfigMaps (Task 3)
│   │   ├── ca-crl-dp.yaml                        # CA bundle + CRL distribution point over HTTP (Task 4)
│   │   ├── token-issuer.yaml                     # JWKS endpoint over HTTP (Task 5)
│   │   ├── voms-service.yaml                     # VOMS attribute/LSC distribution (Task 6)
│   │   └── krb5-kdc.yaml                         # MIT KDC (Task 7)
│   └── tests/
│       ├── authority_macro_test.yaml
│       ├── ca_crl_test.yaml
│       ├── token_issuer_test.yaml
│       └── kdc_test.yaml
├── charts/brix-common/templates/
│   └── _fetch_sidecar.tpl                       # HTTP→file refresh sidecar container spec (Task 8)
├── images/
│   ├── authority/                               # provisioning + static HTTP distributor image (Task 1)
│   │   ├── Dockerfile
│   │   └── serve.conf                            # nginx serving /crl, /certs (jwks), /voms
│   └── krb5-kdc/                                 # MIT KDC image running kdc_helpers.py (Task 7)
│       └── Dockerfile
├── charts/brix-test-lab/values/
│   ├── values.gsi.yaml                           # x509 authorities + (placeholder) consumer (Task 9)
│   └── values.token.yaml                         # token+krb5 authorities (Task 9)
└── tests-bats/
    ├── authority_image.bats                      # Task 1
    └── auth_authority_e2e.bats                    # Task 9 (opt-in live)
```

---

## Task 1: `images/authority` — provisioning + static distributor image

**Files:**
- Create: `k8s-tests/images/authority/Dockerfile`
- Create: `k8s-tests/images/authority/serve.conf`
- Create: `k8s-tests/tests-bats/authority_image.bats`

**Interfaces:**
- Produces image `brix-authority:dev` containing: python3, openssl, the repo `tests/` + `utils/` provisioning scripts (copied in), MIT krb5 workstation tools, and nginx. Two roles by `CMD`: (a) run a provisioning script; (b) `nginx -g 'daemon off;'` serving `/crl/`, `/certs/`, `/voms/` from `/srv/dist`.

- [ ] **Step 1: Write the failing test**

`k8s-tests/tests-bats/authority_image.bats`:
```bash
#!/usr/bin/env bats
IMG_DIR="${BATS_TEST_DIRNAME}/../images/authority"
REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
TAG="brix-authority:batstest"

setup() { docker build -q -t "$TAG" -f "$IMG_DIR/Dockerfile" "$REPO_ROOT" >/dev/null; }
teardown() { docker rmi -f "$TAG" >/dev/null 2>&1 || true; }

@test "authority image bundles the provisioning scripts and tools" {
  run docker run --rm "$TAG" bash -lc 'test -f /opt/brix/tests/pki_helpers.py && test -f /opt/brix/utils/make_token.py && command -v openssl && command -v kadmin.local && command -v nginx'
  [ "$status" -eq 0 ]
}

@test "authority image can generate a CA into a work dir" {
  run docker run --rm -e PKI_DIR=/tmp/pki "$TAG" bash -lc 'cd /opt/brix && PKI_DIR=/tmp/pki python3 -c "import sys; sys.path.insert(0,\"tests\"); from pki_helpers import blitz_test_pki; blitz_test_pki()" && test -f /tmp/pki/ca/ca.pem'
  [ "$status" -eq 0 ]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/authority_image.bats`
Expected: FAIL — Dockerfile does not exist.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/images/authority/serve.conf`:
```nginx
worker_processes 1;
events { worker_connections 64; }
http {
  server {
    listen 8080;
    root /srv/dist;
    autoindex on;
    location /healthz { return 200 "ok\n"; }
    location /crl/   { }
    location /certs/ { }   # jwks.json + ca bundle
    location /voms/  { }
  }
}
```

`k8s-tests/images/authority/Dockerfile` (build context = repo root, so it can COPY `tests/` and `utils/`):
```dockerfile
# authority — provisioning tools + static HTTP distributor for the auth plane.
FROM almalinux:9
RUN dnf install -y python3 python3-pip openssl nginx \
        krb5-server krb5-workstation voms-clients \
    && dnf clean all
RUN python3 -m pip install --no-cache-dir cryptography pyjwt
WORKDIR /opt/brix
COPY tests/ /opt/brix/tests/
COPY utils/ /opt/brix/utils/
COPY k8s-tests/images/authority/serve.conf /etc/nginx/nginx.conf
RUN mkdir -p /srv/dist/crl /srv/dist/certs /srv/dist/voms
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/authority_image.bats`
Expected: PASS (2 tests). If `pip install cryptography` is slow, allow the build a few minutes.

- [ ] **Step 5: Checkpoint (no git)**

Confirm both bats tests are green and `docker images | grep brix-authority` shows the built image was removed by teardown (clean). Do not commit.

---

## Task 2: `_authority.tpl` — shared authority Deployment+Service macro

**Files:**
- Create: `k8s-tests/charts/auth-authority/Chart.yaml`
- Create: `k8s-tests/charts/auth-authority/values.yaml`
- Create: `k8s-tests/charts/auth-authority/templates/_authority.tpl`
- Create: `k8s-tests/charts/auth-authority/tests/authority_macro_test.yaml`

**Interfaces:**
- Consumes: `brix-common` helpers.
- Produces: `auth-authority.deploymentService` — a macro rendering one Deployment + one ClusterIP Service for an authority. Called with a dict: `(dict "root" $ "name" "grid-ca" "port" 8080 "image" ... "volumes" ... "mounts" ... "command" ...)`. Every authority in later tasks is rendered through this one macro (DRY).

- [ ] **Step 1: Write the failing test**

`k8s-tests/charts/auth-authority/tests/authority_macro_test.yaml`:
```yaml
suite: authority macro
templates:
  - templates/_probe.yaml          # a test-only template that invokes the macro
release:
  name: rel
tests:
  - it: renders a Deployment and a Service named for the authority
    documentIndex: 0
    asserts:
      - isKind: { of: Deployment }
      - equal: { path: metadata.name, value: rel-grid-ca }
  - it: service targets the authority port
    documentIndex: 1
    asserts:
      - isKind: { of: Service }
      - equal: { path: spec.ports[0].port, value: 8080 }
      - equal: { path: spec.selector["app.kubernetes.io/component"], value: grid-ca }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm dependency build k8s-tests/charts/auth-authority 2>/dev/null || true; helm unittest k8s-tests/charts/auth-authority`
Expected: FAIL — chart + macro do not exist.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/charts/auth-authority/Chart.yaml`:
```yaml
apiVersion: v2
name: auth-authority
description: x509/token/krb5 authority site-services for the test lab
type: application
version: 0.1.0
appVersion: "0.1.0"
dependencies:
  - name: brix-common
    version: 0.1.0
    repository: file://../brix-common
```

`k8s-tests/charts/auth-authority/values.yaml`:
```yaml
image: { repository: brix-authority, tag: dev, pullPolicy: Never }
kdcImage: { repository: brix-krb5-kdc, tag: dev, pullPolicy: Never }
realm: NGINX.TEST
issuer: https://test.example.com
audience: nginx-xrootd
enabled:
  ca: true
  token: true
  voms: true
  krb5: true
```

`k8s-tests/charts/auth-authority/templates/_authority.tpl`:
```yaml
{{/*
auth-authority.deploymentService — one Deployment + one Service for an authority.
Args (dict): root(.), name, port, image(dict repo/tag/pullPolicy), command(list),
             mounts(list), volumes(list).
*/}}
{{- define "auth-authority.deploymentService" -}}
{{- $root := .root -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $root.Release.Name }}-{{ .name }}
  labels:
    {{- include "brix-common.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "brix-common.selectorLabels" $root | nindent 6 }}
      app.kubernetes.io/component: {{ .name }}
  template:
    metadata:
      labels:
        {{- include "brix-common.labels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ .name }}
    spec:
      containers:
        - name: {{ .name }}
          image: "{{ .image.repository }}:{{ .image.tag }}"
          imagePullPolicy: {{ .image.pullPolicy | default "Never" }}
          {{- with .command }}
          command: {{ toYaml . | nindent 12 }}
          {{- end }}
          ports:
            - containerPort: {{ .port }}
          {{- with .mounts }}
          volumeMounts: {{ toYaml . | nindent 12 }}
          {{- end }}
      {{- with .volumes }}
      volumes: {{ toYaml . | nindent 8 }}
      {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $root.Release.Name }}-{{ .name }}
  labels:
    {{- include "brix-common.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
spec:
  type: ClusterIP
  selector:
    {{- include "brix-common.selectorLabels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
  ports:
    - name: svc
      port: {{ .port }}
      targetPort: {{ .port }}
{{- end -}}
```

Test-only probe `k8s-tests/charts/auth-authority/templates/_probe.yaml` (guarded so it never renders in real installs):
```yaml
{{- if .Values.renderProbe }}
{{ include "auth-authority.deploymentService" (dict "root" . "name" "grid-ca" "port" 8080 "image" .Values.image) }}
{{- end }}
```
And add `renderProbe: false` to `values.yaml`. The unittest sets `renderProbe: true` — append this to each test's `set:` block:
```yaml
    set:
      renderProbe: true
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm dependency build k8s-tests/charts/auth-authority && helm unittest k8s-tests/charts/auth-authority`
Expected: PASS (2 tests).

- [ ] **Step 5: Checkpoint (no git)** — macro renders a Deployment+Service pair; verify `helm template` with `renderProbe=true` shows exactly 2 documents. Do not commit.

---

## Task 3: Bootstrap Job + RBAC — provision material into Secrets/ConfigMaps

**Files:**
- Create: `k8s-tests/charts/auth-authority/templates/bootstrap-rbac.yaml`
- Create: `k8s-tests/charts/auth-authority/templates/bootstrap-job.yaml`
- Modify: `k8s-tests/charts/auth-authority/tests/authority_macro_test.yaml` (add a bootstrap suite) or add `tests/bootstrap_test.yaml`

**Interfaces:**
- Produces (at runtime, in the release namespace):
  - Secret `<rel>-pki` — keys `ca.pem`, `hostcert.pem`, `hostkey.pem`, `usercert.pem`, `userkey.pem`, `userproxy.pem`, `signing_key.pem`, `brix.keytab`.
  - ConfigMap `<rel>-ca-bundle` — `ca.pem`, `<hash>.0`.
  - ConfigMap `<rel>-crl` — `test-user.crl.pem`.
  - ConfigMap `<rel>-jwks` — `jwks.json`.
  - ConfigMap `<rel>-vomsdir` — vomsdir `.lsc` files.
  - ConfigMap `<rel>-krb5` — `krb5.conf`.
- These names are the stable contract every consumer (authorities here, servers in #3) mounts.

- [ ] **Step 1: Write the failing test**

`k8s-tests/charts/auth-authority/tests/bootstrap_test.yaml`:
```yaml
suite: bootstrap job + rbac
templates:
  - templates/bootstrap-job.yaml
  - templates/bootstrap-rbac.yaml
release:
  name: rel
tests:
  - it: is a pre-install/pre-upgrade hook Job
    templates: [templates/bootstrap-job.yaml]
    asserts:
      - isKind: { of: Job }
      - equal:
          path: metadata.annotations["helm.sh/hook"]
          value: pre-install,pre-upgrade
      - equal:
          path: spec.template.spec.serviceAccountName
          value: rel-bootstrap
  - it: grants secret+configmap write via Role
    templates: [templates/bootstrap-rbac.yaml]
    documentIndex: 1
    asserts:
      - isKind: { of: Role }
      - contains:
          path: rules[0].resources
          content: secrets
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm unittest k8s-tests/charts/auth-authority -f tests/bootstrap_test.yaml`
Expected: FAIL — templates absent.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/charts/auth-authority/templates/bootstrap-rbac.yaml`:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Release.Name }}-bootstrap
  labels: {{- include "brix-common.labels" . | nindent 4 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Release.Name }}-bootstrap
  labels: {{- include "brix-common.labels" . | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: [secrets, configmaps]
    verbs: [create, update, patch, get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Release.Name }}-bootstrap
  labels: {{- include "brix-common.labels" . | nindent 4 }}
subjects:
  - kind: ServiceAccount
    name: {{ .Release.Name }}-bootstrap
roleRef:
  kind: Role
  name: {{ .Release.Name }}-bootstrap
  apiGroup: rbac.authorization.k8s.io
```

`k8s-tests/charts/auth-authority/templates/bootstrap-job.yaml` — a Job that (a) runs the provisioning scripts into `/work`, (b) creates the Secrets/ConfigMaps with `kubectl create ... --dry-run=client -o yaml | kubectl apply -f -` (idempotent). The image bundles the scripts; it also needs `kubectl` — install it in the authority image or use a kubectl sidecar. To keep the authority image lean, the Job uses **two init/main containers sharing an emptyDir**: main container provisions, then a `bitnami/kubectl`-equivalent... but that reintroduces an external image. Instead, add `kubectl` to the authority image (single line) and give this Job the service account.

Add to `images/authority/Dockerfile` (Task 1 amendment — record here and apply): 
```dockerfile
RUN curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" && chmod +x /usr/local/bin/kubectl
```
Then the Job body:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .Release.Name }}-bootstrap
  labels: {{- include "brix-common.labels" . | nindent 4 }}
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-delete-policy: before-hook-creation
spec:
  backoffLimit: 1
  template:
    metadata:
      labels: {{- include "brix-common.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ .Release.Name }}-bootstrap
      restartPolicy: Never
      containers:
        - name: provision
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy | default "Never" }}
          env:
            - { name: PKI_DIR, value: /work/pki }
            - { name: TOKEN_DIR, value: /work/tokens }
            - { name: NS, value: "{{ .Release.Namespace }}" }
            - { name: REL, value: "{{ .Release.Name }}" }
            - { name: REALM, value: "{{ .Values.realm }}" }
          command: ["/bin/bash", "-lc"]
          args:
            - |
              set -euo pipefail
              cd /opt/brix
              mkdir -p "$PKI_DIR" "$TOKEN_DIR"
              PKI_DIR="$PKI_DIR" python3 -c 'import sys; sys.path.insert(0,"tests"); from pki_helpers import blitz_test_pki; blitz_test_pki()'
              python3 utils/make_proxy.py "$PKI_DIR" || true
              python3 utils/make_token.py init "$TOKEN_DIR"
              # publish private material
              kubectl create secret generic "$REL-pki" -n "$NS" \
                --from-file=ca.pem="$PKI_DIR/ca/ca.pem" \
                --from-file=hostcert.pem="$PKI_DIR/server/hostcert.pem" \
                --from-file=hostkey.pem="$PKI_DIR/server/hostkey.pem" \
                --from-file=usercert.pem="$PKI_DIR/user/usercert.pem" \
                --from-file=userkey.pem="$PKI_DIR/user/userkey.pem" \
                --from-file=signing_key.pem="$TOKEN_DIR/signing_key.pem" \
                --dry-run=client -o yaml | kubectl apply -f -
              # publish public material
              kubectl create configmap "$REL-ca-bundle" -n "$NS" --from-file="$PKI_DIR/ca/" --dry-run=client -o yaml | kubectl apply -f -
              kubectl create configmap "$REL-crl" -n "$NS" --from-file=test-user.crl.pem="$PKI_DIR/ca/test-user.crl.pem" --dry-run=client -o yaml | kubectl apply -f -
              kubectl create configmap "$REL-jwks" -n "$NS" --from-file=jwks.json="$TOKEN_DIR/jwks.json" --dry-run=client -o yaml | kubectl apply -f -
              kubectl create configmap "$REL-vomsdir" -n "$NS" --from-file="$PKI_DIR/vomsdir/" --dry-run=client -o yaml | kubectl apply -f - || true
              echo "bootstrap complete"
          volumeMounts:
            - { name: work, mountPath: /work }
      volumes:
        - { name: work, emptyDir: {} }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm unittest k8s-tests/charts/auth-authority`
Expected: PASS (all suites). Rendering-only; runtime is exercised in Task 9's live e2e.

- [ ] **Step 5: Checkpoint (no git)** — verify `helm template` renders the Job with the hook annotation and the RBAC trio. Do not commit.

---

## Task 4: CA + CRL distribution point (serves over HTTP)

**Files:**
- Create: `k8s-tests/charts/auth-authority/templates/ca-crl-dp.yaml`
- Create: `k8s-tests/charts/auth-authority/tests/ca_crl_test.yaml`

**Interfaces:**
- Consumes: ConfigMaps `<rel>-ca-bundle`, `<rel>-crl` (Task 3).
- Produces: Service `<rel>-grid-ca:8080` serving `/certs/ca.pem`, `/crl/test-user.crl.pem`, `/healthz`. This URL is the CRL distribution point the fetch sidecar (Task 8) pulls.

- [ ] **Step 1: Write the failing test**

`tests/ca_crl_test.yaml`:
```yaml
suite: ca + crl distribution point
templates:
  - templates/ca-crl-dp.yaml
release:
  name: rel
tests:
  - it: renders the grid-ca authority when ca is enabled
    set: { enabled: { ca: true } }
    asserts:
      - hasDocuments: { count: 2 }   # Deployment + Service
      - equal:
          path: metadata.name
          value: rel-grid-ca
          documentIndex: 0
  - it: mounts the crl + ca-bundle configmaps into the distributor
    set: { enabled: { ca: true } }
    documentIndex: 0
    asserts:
      - contains:
          path: spec.template.spec.volumes
          content:
            name: crl
            configMap: { name: rel-crl }
  - it: renders nothing when ca disabled
    set: { enabled: { ca: false } }
    asserts:
      - hasDocuments: { count: 0 }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm unittest k8s-tests/charts/auth-authority -f tests/ca_crl_test.yaml`
Expected: FAIL — template absent.

- [ ] **Step 3: Write the minimal implementation**

`templates/ca-crl-dp.yaml` — calls the Task-2 macro with volumes mapping the ConfigMaps into `/srv/dist`:
```yaml
{{- if .Values.enabled.ca }}
{{ include "auth-authority.deploymentService" (dict
    "root" .
    "name" "grid-ca"
    "port" 8080
    "image" .Values.image
    "mounts" (list
       (dict "name" "crl"     "mountPath" "/srv/dist/crl")
       (dict "name" "ca"      "mountPath" "/srv/dist/certs"))
    "volumes" (list
       (dict "name" "crl" "configMap" (dict "name" (printf "%s-crl" .Release.Name)))
       (dict "name" "ca"  "configMap" (dict "name" (printf "%s-ca-bundle" .Release.Name))))
  ) }}
{{- end }}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm unittest k8s-tests/charts/auth-authority`
Expected: PASS.

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 5: Token issuer (JWKS over HTTP)

**Files:**
- Create: `k8s-tests/charts/auth-authority/templates/token-issuer.yaml`
- Create: `k8s-tests/charts/auth-authority/tests/token_issuer_test.yaml`

**Interfaces:**
- Consumes: ConfigMap `<rel>-jwks` (Task 3).
- Produces: Service `<rel>-token-issuer:8080` serving `/certs/jwks.json`. Servers' JWKS fetch sidecar pulls this; `brix_token_issuer`/`brix_token_audience` remain the fixed constants.

- [ ] **Step 1: Write the failing test**

`tests/token_issuer_test.yaml`:
```yaml
suite: token issuer
templates: [templates/token-issuer.yaml]
release: { name: rel }
tests:
  - it: serves jwks from the jwks configmap when token enabled
    set: { enabled: { token: true } }
    documentIndex: 0
    asserts:
      - equal: { path: metadata.name, value: rel-token-issuer }
      - contains:
          path: spec.template.spec.volumes
          content: { name: jwks, configMap: { name: rel-jwks } }
  - it: absent when token disabled
    set: { enabled: { token: false } }
    asserts:
      - hasDocuments: { count: 0 }
```

- [ ] **Step 2: Run** `helm unittest ... -f tests/token_issuer_test.yaml` → FAIL (template absent).

- [ ] **Step 3: Write** `templates/token-issuer.yaml`:
```yaml
{{- if .Values.enabled.token }}
{{ include "auth-authority.deploymentService" (dict
    "root" .
    "name" "token-issuer"
    "port" 8080
    "image" .Values.image
    "mounts" (list (dict "name" "jwks" "mountPath" "/srv/dist/certs"))
    "volumes" (list (dict "name" "jwks" "configMap" (dict "name" (printf "%s-jwks" .Release.Name))))
  ) }}
{{- end }}
```

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/auth-authority` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 6: VOMS service

**Files:**
- Create: `k8s-tests/charts/auth-authority/templates/voms-service.yaml`
- Add a suite to `tests/token_issuer_test.yaml` or new `tests/voms_test.yaml`.

**Interfaces:**
- Consumes: ConfigMap `<rel>-vomsdir` (Task 3).
- Produces: Service `<rel>-voms:8080` serving `/voms/` (the `.lsc`/vomsdir tree). Consumed by WebDAV GSI+VOMS servers (#3/#4) which mount the vomsdir ConfigMap directly (the Service exists for parity/inspection and future dynamic AC issuance).

- [ ] **Step 1: Write the failing test** `k8s-tests/charts/auth-authority/tests/voms_test.yaml`:
```yaml
suite: voms service
templates: [templates/voms-service.yaml]
release: { name: rel }
tests:
  - it: renders voms authority when enabled
    set: { enabled: { voms: true } }
    documentIndex: 0
    asserts:
      - equal: { path: metadata.name, value: rel-voms }
  - it: absent when disabled
    set: { enabled: { voms: false } }
    asserts:
      - hasDocuments: { count: 0 }
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Write** `templates/voms-service.yaml`:
```yaml
{{- if .Values.enabled.voms }}
{{ include "auth-authority.deploymentService" (dict
    "root" .
    "name" "voms"
    "port" 8080
    "image" .Values.image
    "mounts" (list (dict "name" "vomsdir" "mountPath" "/srv/dist/voms"))
    "volumes" (list (dict "name" "vomsdir" "configMap" (dict "name" (printf "%s-vomsdir" .Release.Name))))
  ) }}
{{- end }}
```
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 7: krb5 KDC

**Files:**
- Create: `k8s-tests/images/krb5-kdc/Dockerfile`
- Create: `k8s-tests/charts/auth-authority/templates/krb5-kdc.yaml`
- Create: `k8s-tests/charts/auth-authority/tests/kdc_test.yaml`

**Interfaces:**
- Produces image `brix-krb5-kdc:dev` running `kdc_helpers.py up` (realm `NGINX.TEST`, KDC on 88/tcp+udp) and keeping the KDC in the foreground. Produces Service `<rel>-krb5-kdc` exposing 88/tcp+udp. The Job (Task 3) publishes `krb5.conf` + `brix.keytab`; the KDC pod owns the realm database (an emptyDir for the lab; the keytab is regenerated by the KDC and re-published, so the Job and KDC must agree — see note).

Note on keytab ownership: to avoid a split-brain between the Job's keytab and the KDC's database, the **KDC pod is the single owner** of the realm DB and keytab. Adjust Task 3: the Job does *not* run `kdc_helpers.py`; instead, after the KDC pod is Ready, the KDC's own init publishes `krb5.conf` + `brix.keytab` into ConfigMap `<rel>-krb5` / Secret `<rel>-pki` (keytab key) via kubectl. Implement that as an in-pod post-start step here.

- [ ] **Step 1: Write the failing test** `tests/kdc_test.yaml`:
```yaml
suite: krb5 kdc
templates: [templates/krb5-kdc.yaml]
release: { name: rel }
tests:
  - it: exposes kerberos 88 tcp and udp when krb5 enabled
    set: { enabled: { krb5: true } }
    documentIndex: 1     # Service
    asserts:
      - isKind: { of: Service }
      - contains:
          path: spec.ports
          content: { name: kdc-udp, port: 88, protocol: UDP }
  - it: absent when disabled
    set: { enabled: { krb5: false } }
    asserts:
      - hasDocuments: { count: 0 }
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Write the implementation.**

`k8s-tests/images/krb5-kdc/Dockerfile` (context = repo root, to COPY `tests/kdc_helpers.py`):
```dockerfile
FROM almalinux:9
RUN dnf install -y krb5-server krb5-workstation python3 && dnf clean all
RUN curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" && chmod +x /usr/local/bin/kubectl
COPY tests/ /opt/brix/tests/
WORKDIR /opt/brix
CMD ["/bin/bash","-lc","python3 tests/kdc_helpers.py up && \
     kubectl create configmap $REL-krb5 -n $NS --from-file=krb5.conf=$KRB5_CONF --dry-run=client -o yaml | kubectl apply -f - && \
     kubectl create secret generic $REL-pki -n $NS --from-file=brix.keytab=$KRB5_KEYTAB --dry-run=client -o yaml | kubectl apply -f - --field-manager=kdc || true && \
     sleep infinity"]
```
(Because both the bootstrap Job and the KDC touch Secret `$REL-pki`, use `kubectl patch`/`apply` merge semantics; the keytab key is KDC-owned, PKI keys are Job-owned — different keys in the same Secret, so applies don't clobber. The KDC uses `apply` which merges by key.)

`templates/krb5-kdc.yaml` — custom (native ports, needs the SA to publish), so it does not use the generic macro:
```yaml
{{- if .Values.enabled.krb5 }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-krb5-kdc
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
    app.kubernetes.io/component: krb5-kdc
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "brix-common.selectorLabels" . | nindent 6 }}
      app.kubernetes.io/component: krb5-kdc
  template:
    metadata:
      labels:
        {{- include "brix-common.labels" . | nindent 8 }}
        app.kubernetes.io/component: krb5-kdc
    spec:
      serviceAccountName: {{ .Release.Name }}-bootstrap
      containers:
        - name: krb5-kdc
          image: "{{ .Values.kdcImage.repository }}:{{ .Values.kdcImage.tag }}"
          imagePullPolicy: {{ .Values.kdcImage.pullPolicy | default "Never" }}
          env:
            - { name: NS,  value: "{{ .Release.Namespace }}" }
            - { name: REL, value: "{{ .Release.Name }}" }
            - { name: KRB5_CONF,   value: /opt/brix/krb5/krb5.conf }
            - { name: KRB5_KEYTAB, value: /opt/brix/krb5/brix.keytab }
          ports:
            - { name: kdc-tcp, containerPort: 88, protocol: TCP }
            - { name: kdc-udp, containerPort: 88, protocol: UDP }
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-krb5-kdc
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
    app.kubernetes.io/component: krb5-kdc
spec:
  selector:
    {{- include "brix-common.selectorLabels" . | nindent 4 }}
    app.kubernetes.io/component: krb5-kdc
  ports:
    - { name: kdc-tcp, port: 88, targetPort: 88, protocol: TCP }
    - { name: kdc-udp, port: 88, targetPort: 88, protocol: UDP }
{{- end }}
```

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/auth-authority` → PASS (all suites).
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 8: `brix-common._fetch_sidecar` — HTTP→file refresh container

**Files:**
- Create: `k8s-tests/charts/brix-common/templates/_fetch_sidecar.tpl`
- Create: `k8s-tests/charts/auth-authority/tests/fetch_sidecar_test.yaml` (tested through the probe)

**Interfaces:**
- Produces: `brix-common.fetchSidecar` — a container spec (YAML) that loops `curl <url> -o <dest>` every `<interval>` seconds into a shared `emptyDir`. Args (dict): `name`, `url`, `dest`, `interval`, `volumeName`. Consumed by #3/#4 server pods to keep the CRL/JWKS file fresh.

- [ ] **Step 1: Write the failing test** `k8s-tests/charts/auth-authority/tests/fetch_sidecar_test.yaml` (render via the probe template, extended to accept a sidecar):

Extend `templates/_probe.yaml`:
```yaml
{{- if .Values.renderFetchProbe }}
apiVersion: v1
kind: Pod
metadata: { name: fetch-probe }
spec:
  containers:
    - {{ include "brix-common.fetchSidecar" (dict "name" "crl-refresh" "url" "http://rel-grid-ca:8080/crl/test-user.crl.pem" "dest" "/shared/crl.pem" "interval" 30 "volumeName" "shared") | nindent 6 | trim }}
  volumes:
    - { name: shared, emptyDir: {} }
{{- end }}
```
Test:
```yaml
suite: fetch sidecar
templates: [templates/_probe.yaml]
release: { name: rel }
tests:
  - it: emits a curl-loop container writing to the dest
    set: { renderFetchProbe: true }
    asserts:
      - equal:
          path: spec.containers[0].name
          value: crl-refresh
      - matchRegex:
          path: spec.containers[0].args[0]
          pattern: "curl .*grid-ca:8080/crl/test-user.crl.pem.*-o /shared/crl.pem"
```
Add `renderFetchProbe: false` to `values.yaml`.

- [ ] **Step 2: Run → FAIL** (helper undefined).

- [ ] **Step 3: Write** `k8s-tests/charts/brix-common/templates/_fetch_sidecar.tpl`:
```yaml
{{/*
brix-common.fetchSidecar — a container that refreshes url->dest every interval s.
Args(dict): name, url, dest, interval, volumeName.
*/}}
{{- define "brix-common.fetchSidecar" -}}
name: {{ .name }}
image: brix-authority:dev
imagePullPolicy: Never
command: ["/bin/sh","-c"]
args:
  - |
    while true; do
      curl -fsS {{ .url }} -o {{ .dest }}.tmp && mv {{ .dest }}.tmp {{ .dest }} || echo "fetch {{ .name }} failed" >&2
      sleep {{ .interval }}
    done
volumeMounts:
  - name: {{ .volumeName }}
    mountPath: {{ dir .dest }}
{{- end -}}
```

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/auth-authority -f tests/fetch_sidecar_test.yaml` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 9: Wire into umbrella + profiles + live e2e

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `auth-authority` dependency, condition `auth-authority.enabled`)
- Create: `k8s-tests/charts/brix-test-lab/values/values.gsi.yaml`
- Create: `k8s-tests/charts/brix-test-lab/values/values.token.yaml`
- Modify: `k8s-tests/xrd-lab` (`build_images` builds authority + kdc images; add a `test authorities` scenario)
- Create: `k8s-tests/tests-bats/auth_authority_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab deploy gsi` / `deploy token` bring up the authority plane; `xrd-lab test authorities` asserts CRL + JWKS are fetchable over HTTP from within the cluster.

- [ ] **Step 1: Write the failing test** `k8s-tests/tests-bats/auth_authority_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip "set XRD_LAB_E2E=1"
  "$LAB" up
  "$LAB" deploy gsi
}
teardown_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] && "$LAB" down gsi || true; }

@test "CRL is served over HTTP by the grid-ca authority" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  run "$LAB" test authorities
  [ "$status" -eq 0 ]
  [[ "$output" == *"CRL OK"* ]]
  [[ "$output" == *"JWKS OK"* ]]
}

@test "dry-run authorities scenario curls the CA and issuer services" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test authorities
  [ "$status" -eq 0 ]
  [[ "$output" == *"grid-ca"* ]]
  [[ "$output" == *"token-issuer"* ]]
}
```

- [ ] **Step 2: Run → FAIL** (scenario + profile missing).

- [ ] **Step 3: Implement.**

Add to `charts/brix-test-lab/Chart.yaml` dependencies:
```yaml
  - name: auth-authority
    version: 0.1.0
    repository: file://../auth-authority
    condition: auth-authority.enabled
```

`charts/brix-test-lab/values/values.gsi.yaml`:
```yaml
auth-authority:
  enabled: true
  enabledSub: { ca: true, token: false, voms: true, krb5: false }
smoke: { enabled: false }
```
(Map `enabledSub`→ the subchart's `enabled` block; simplest is to set the subchart values directly:)
```yaml
auth-authority:
  enabled: true
  enabled: { ca: true, token: false, voms: true, krb5: false }
```
Note: Helm merges the subchart's own `enabled` map; the umbrella condition uses a separate top-level `auth-authority.enabled` boolean. To avoid the name clash, rename the subchart's per-authority map to `services:` in `auth-authority/values.yaml` and every template (`.Values.services.ca` etc.), reserving `enabled` for the umbrella condition. Apply that rename now across Tasks 2–7 templates.

`charts/brix-test-lab/values/values.token.yaml`:
```yaml
auth-authority:
  enabled: true
  services: { ca: true, token: true, voms: false, krb5: true }
smoke: { enabled: false }
```

`xrd-lab` — extend `build_images` to also build authority images when the profile needs them, and add the scenario. In `build_images`:
```bash
    if [ "${1:-}" = "auth" ] || [ "$XRD_LAB_DRY_RUN" = "1" ]; then
        run minikube image build -t brix-authority:dev "$LAB_DIR/images/authority" -f "$LAB_DIR/images/authority/Dockerfile" --build-opt=context="$LAB_DIR/.."
        run minikube image build -t brix-krb5-kdc:dev "$LAB_DIR/images/krb5-kdc" -f "$LAB_DIR/images/krb5-kdc/Dockerfile" --build-opt=context="$LAB_DIR/.."
    fi
```
(Real `minikube image build` builds from a context dir; since the authority image needs the repo root as context, pass the repo root as the positional context and `-f` the Dockerfile. Verify the exact `minikube image build` context flag at implementation time; fall back to `docker build` + `minikube image load` if needed.)

Add `scenario_authorities` to `xrd-lab`:
```bash
scenario_authorities() {
    local ns="brix-${1:-gsi}"
    if [ "$DRY_RUN" = "1" ]; then
        echo "kubectl -n $ns run probe --image=brix-authority:dev -- curl -fsS http://<rel>-grid-ca:8080/crl/test-user.crl.pem"
        echo "kubectl -n $ns run probe --image=brix-authority:dev -- curl -fsS http://<rel>-token-issuer:8080/certs/jwks.json"
        return 0
    fi
    local rel="brix-${1:-gsi}"
    local crl jwks
    crl="$(kubectl -n "$ns" run crlprobe-$$ --rm -i --restart=Never --image=brix-authority:dev --image-pull-policy=Never --quiet --command -- \
        curl -fsS -o /dev/null -w '%{http_code}' "http://${rel}-grid-ca:8080/crl/test-user.crl.pem" 2>/dev/null || true)"
    [ "$crl" = "200" ] && echo "CRL OK" || { echo "CRL FAILED ($crl)" >&2; return 1; }
    jwks="$(kubectl -n "$ns" run jwksprobe-$$ --rm -i --restart=Never --image=brix-authority:dev --image-pull-policy=Never --quiet --command -- \
        curl -fsS -o /dev/null -w '%{http_code}' "http://${rel}-token-issuer:8080/certs/jwks.json" 2>/dev/null || true)"
    [ "$jwks" = "200" ] && echo "JWKS OK" || echo "JWKS SKIP (token issuer not in this profile)"
}
```
Register `authorities)` in `cmd_test`'s case.

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/auth_authority_e2e.bats        # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
helm dependency build k8s-tests/charts/brix-test-lab
helm template brix-gsi k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.gsi.yaml | kubeconform -strict -summary
```
Expected: dry-run bats PASS; shellcheck clean; kubeconform `Invalid: 0`.

Then the live gate:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/auth_authority_e2e.bats
```
Expected: `CRL OK` and `JWKS OK` — the bootstrap Job provisioned real material and the grid-ca/token-issuer Services serve it over HTTP.

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #1)

- [ ] `helm unittest k8s-tests/charts/auth-authority` → all suites PASS.
- [ ] `helm template brix-token k8s-tests/charts/brix-test-lab -f .../values.token.yaml | kubeconform -strict -summary` → `Invalid: 0`.
- [ ] `XRD_LAB_E2E=1 bats k8s-tests/tests-bats/auth_authority_e2e.bats` → `CRL OK`, `JWKS OK`.
- [ ] **DoD (spec §5 row 1):** a consumer can pull a CRL over HTTP and validate JWKS over HTTP from the authority Services. ✅ when the live gate is green. (Full server-side consumption is exercised when #3 lands and mounts `<rel>-ca-bundle` + runs the fetch sidecar.)

## Self-review notes

- **Spec coverage:** §4.2 CA/CRL over HTTP → Tasks 1,3,4; VOMS → Task 6; token/JWKS over HTTP → Tasks 3,5; krb5 KDC → Tasks 3(note),7; bootstrap Job publishing Secrets/ConfigMaps → Task 3; repo-CA-over-cert-manager stance honored (uses `pki_helpers`/`make_crl`, no cert-manager); fetch-over-HTTP consumption pattern → Task 8.
- **Placeholder scan:** the two implementation-time verifications flagged inline (exact `minikube image build` context flag; keytab/Secret key-merge ownership) are explicit engineering notes with a stated fallback, not TODOs. The `<rel>` literal in the dry-run echo is a human-readable placeholder in a *print-only* branch, not executed.
- **Name consistency:** Secret/ConfigMap contract names (`<rel>-pki`, `<rel>-ca-bundle`, `<rel>-crl`, `<rel>-jwks`, `<rel>-vomsdir`, `<rel>-krb5`) are defined in Task 3 and referenced identically in Tasks 4–7; the per-authority gate map is renamed `services` (Task 9) to free `enabled` for the umbrella condition — apply the rename across Tasks 2–7 when reached.
