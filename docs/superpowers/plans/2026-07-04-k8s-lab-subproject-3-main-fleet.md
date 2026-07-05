# K8s Test Lab — Sub-project #3: Main Fleet + Test Runner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Checkbox (`- [ ]`) steps. **No git commands** — "Checkpoint (no git)" is a verification gate.

**Goal:** Deploy the always-on multi-auth single-role fleet (anon / gsi / tls / token `root://`, WebDAV, S3, metrics, plus the reference stock-XRootD) consuming the #1 authority plane, and run the real pytest suite (`--fast`/`--pr`/`--nightly` tiers) against it with JUnit result collection.

**Architecture:** A `main-fleet` subchart renders one Deployment+Service per auth role from `tests/configs/nginx_shared.conf` (split per-listen into role configs, using `brix_*` directives). Auth roles mount the #1 `<rel>-ca-bundle` and run the #1 `brix-common.fetchSidecar` to refresh CRL/JWKS. The `test-runner` subchart (from #2) is extended with tiered selections, `TEST_*` env pointed at fleet Service DNS, and a JUnit-to-PVC result step. Depends on #0, #1, and #2's `test-runner`/`brix-server` image.

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, nginx-xrootd server image, pytest.

**Spec:** §4.4. **Dependencies:** #0, #1 (authorities + Secret/ConfigMap contract), #2 (`brix-server:dev`, `brix-test-runner:dev`, `test-runner` subchart).

## Global Constraints

- Inherits all #0 constraints.
- **Directives are `brix_*`, not `xrootd_*`.** The legacy `k8s-tests/server-helm/templates/configmap.yaml` uses `xrootd_*` names that no longer exist post-rebrand; the new configs use the verified `brix_*` directives from `tests/configs/nginx_shared.conf`. The old `server-helm` chart is retired at the end of this sub-project.
- **Fleet consumes authorities over the network.** CA trust via mounted `<rel>-ca-bundle` ConfigMap; CRL + JWKS refreshed into an `emptyDir` file by the fetch sidecar. Issuer/audience constants match #1 (`https://test.example.com` / `nginx-xrootd`).
- **The suite runs unmodified**, wired only through `TEST_SERVER_HOST` + `TEST_*_PORT` env.

## Fleet roles (verified from `tests/configs/nginx_shared.conf` + `tests/lib/pki.sh` defaults)

| Role (Service suffix) | listen | brix directives | auth material |
|---|---|---|---|
| `anon` | 11094 | `brix_auth none` | — |
| `gsi` | 11095 | `brix_auth gsi` + cert/key/trusted_ca | CA bundle, host cert/key (Secret) |
| `tls` | 11096 | `brix_auth gsi` (TLS-first) | same as gsi |
| `token` | 11097 | `brix_auth token` + jwks/issuer/audience | JWKS file (fetch sidecar) |
| `webdav` | 8443 (ssl) | `brix_webdav` + token/gsi | host cert/key, CA, JWKS |
| `s3` | 9001 | S3 handler | — (SigV4) |
| `metrics` | 9100 | `brix_metrics` | — |
| `reference` | 11098 | stock XRootD (parity) | anon |

---

## File Structure

```
k8s-tests/
├── images/xrootd-reference/Dockerfile          # stock XRootD parity server (Task 5; from existing Dockerfiles/xrootd-reference)
├── charts/main-fleet/
│   ├── Chart.yaml                               # dependency: topology-role (aliased per role) + brix-common
│   ├── values.yaml
│   ├── configs/                                 # per-role brix_* configs split from nginx_shared.conf
│   │   ├── anon.conf  gsi.conf  tls.conf  token.conf  webdav.conf  s3.conf  metrics.conf
│   ├── templates/
│   │   └── reference.yaml                       # stock XRootD Deployment+Service (Task 5)
│   └── tests/
│       ├── roles_test.yaml
│       └── auth_consume_test.yaml
├── charts/topology-role/templates/deployment.yaml   # extended: CA mount + fetch sidecar (Task 3)
├── charts/test-runner/                          # extended from #2 (Tasks 6-7)
│   ├── templates/job.yaml                       # + results PVC, junit args, tier selection
│   └── tests/tier_test.yaml
├── charts/brix-test-lab/values/
│   ├── values.fleet.yaml                        # anon+gsi+token fleet + authorities
│   └── values.fleet-fast.yaml                   # fleet + test-runner fast tier
└── tests-bats/
    ├── fleet_render.bats
    └── fleet_e2e.bats                            # opt-in live
```

---

## Task 1: Split `nginx_shared.conf` into per-role `brix_*` configs

**Files:**
- Create: `k8s-tests/charts/main-fleet/configs/{anon,gsi,tls,token,webdav,s3,metrics}.conf`
- Create: `k8s-tests/charts/main-fleet/Chart.yaml`, `values.yaml`
- Create: `k8s-tests/charts/main-fleet/tests/roles_test.yaml`

**Interfaces:**
- Consumes: `topology-role` (aliased per role), `brix-common`.
- Produces: one config per role using `brix_*` directives, parameterized by `.Values.role.ports[0].port`, `.Values.role.data.root`, and auth material mount paths (`/etc/grid-security/...`, `/etc/brix/jwks/jwks.json`, `/etc/brix/crl/crl.pem`).

- [ ] **Step 1: Write the failing test** `charts/main-fleet/tests/roles_test.yaml`:
```yaml
suite: main-fleet role configs
templates: [charts/gsi/templates/configmap.yaml, charts/token/templates/configmap.yaml]
release: { name: brix-fleet }
tests:
  - it: gsi role uses brix_auth gsi and mounted CA
    templates: [charts/gsi/templates/configmap.yaml]
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_auth gsi" }
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_trusted_ca /etc/grid-security/certificates/ca.pem" }
  - it: token role reads the fetched jwks file and fixed issuer/audience
    templates: [charts/token/templates/configmap.yaml]
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_token_jwks /etc/brix/jwks/jwks.json" }
      - matchRegex: { path: data["nginx.conf"], pattern: 'brix_token_issuer +"https://test.example.com"' }
```

- [ ] **Step 2: Run** `helm dependency build k8s-tests/charts/main-fleet 2>/dev/null||true; helm unittest k8s-tests/charts/main-fleet` → FAIL.

- [ ] **Step 3: Write.** Each config is the corresponding `server{}` block from `tests/configs/nginx_shared.conf`, with `brix_*` directives and mount-path constants. Examples:

`configs/anon.conf`:
```nginx
worker_processes auto;
events { worker_connections 1024; }
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
`configs/gsi.conf`:
```nginx
worker_processes auto;
events { worker_connections 1024; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_storage_backend posix:{{ .Values.role.data.root }};
    brix_auth gsi;
    brix_certificate     /etc/grid-security/hostcert.pem;
    brix_certificate_key /etc/grid-security/hostkey.pem;
    brix_trusted_ca      /etc/grid-security/certificates/ca.pem;
    brix_crl             /etc/brix/crl/crl.pem;
  }
}
```
`configs/token.conf`:
```nginx
worker_processes auto;
events { worker_connections 1024; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_storage_backend posix:{{ .Values.role.data.root }};
    brix_auth token;
    brix_token_jwks     /etc/brix/jwks/jwks.json;
    brix_token_issuer   "https://test.example.com";
    brix_token_audience "nginx-xrootd";
    brix_token_jwks_refresh_interval 5s;
    brix_allow_write on;
  }
}
```
`configs/tls.conf` = gsi.conf with the tls listen port (same directives). `configs/webdav.conf` = the WebDAV `http{}` server block from nginx_shared.conf (ssl_certificate → host cert; `brix_webdav_token_jwks /etc/brix/jwks/jwks.json`; `brix_webdav_cafile /etc/grid-security/certificates/ca.pem`). `configs/s3.conf` = the S3 server block. `configs/metrics.conf`:
```nginx
worker_processes 1;
events { worker_connections 256; }
http { server { listen {{ (index .Values.role.ports 0).port }}; location /metrics { brix_metrics on; } } }
```

`Chart.yaml` aliases `topology-role` per role:
```yaml
apiVersion: v2
name: main-fleet
type: application
version: 0.1.0
dependencies:
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: anon,   condition: anon.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: gsi,    condition: gsi.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: tls,    condition: tls.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: token,  condition: token.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: webdav, condition: webdav.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: s3,     condition: s3.enabled }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: metrics,condition: metrics.enabled }
  - { name: brix-common,   version: 0.1.0, repository: file://../brix-common }
```
`values.yaml` provides each alias its `role` (name/configKey/ports) and `enabled` flags (default anon+gsi+token+webdav+metrics on, tls/s3 off by default).

Because the role configs now live in the **main-fleet** chart but `topology-role`'s ConfigMap reads from `topology-role/configs/`, either (a) also copy these configs into `topology-role/configs/` (keeping topology-role the single config home), or (b) teach `topology-role` to read configs passed as a value. **Decision:** put ALL role configs (chaos + fleet) under `topology-role/configs/` so the generic chart owns config rendering; `configKey` selects among them. Move these 7 files into `topology-role/configs/` and reference `configKey: gsi` etc. Update the test template paths accordingly (the ConfigMap is `charts/<alias>/templates/configmap.yaml` at umbrella render, but for `main-fleet` unit tests the subchart-of-subchart path is `charts/gsi/charts/topology-role/...` — simplest is to unit-test `topology-role` directly with `configKey` set, and test *wiring* at the umbrella level). Adjust `roles_test.yaml` to test `topology-role` directly:
```yaml
suite: fleet role configs
templates: [templates/configmap.yaml]
release: { name: brix-fleet }
tests:
  - it: gsi config
    set: { role: { name: gsi, configKey: gsi, ports: [ { name: xrootd, port: 11095 } ], data: { root: /data/xrootd } } }
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_auth gsi" }
```
(Run this suite from `charts/topology-role` after copying the configs there.)

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/topology-role` (role configs) → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 2: Fleet values — enable/port map + reference

**Files:**
- Finalize: `k8s-tests/charts/main-fleet/values.yaml`
- Create: `k8s-tests/charts/main-fleet/tests/enable_test.yaml`

**Interfaces:**
- Produces: a values contract where each role alias carries `{ enabled, role: { name, configKey, ports, data } }`. Service DNS become `<release>-<role>` (e.g. `brix-fleet-gsi`).

- [ ] **Step 1: Write the failing test** `tests/enable_test.yaml`:
```yaml
suite: fleet enable map
# render the umbrella-style: test that a disabled role produces no Service
templates: [charts/s3/templates/service.yaml]
release: { name: brix-fleet }
tests:
  - it: s3 role is off by default
    asserts:
      - hasDocuments: { count: 0 }
```

- [ ] **Step 2: Run** → FAIL (values not final).

- [ ] **Step 3: Write** `values.yaml`:
```yaml
anon:    { enabled: true,  role: { name: anon,    configKey: anon,    ports: [ { name: xrootd, port: 11094 } ], data: { root: /data/xrootd } } }
gsi:     { enabled: true,  role: { name: gsi,     configKey: gsi,     ports: [ { name: xrootd, port: 11095 } ], data: { root: /data/xrootd } } }
tls:     { enabled: false, role: { name: tls,     configKey: tls,     ports: [ { name: roots,  port: 11096 } ], data: { root: /data/xrootd } } }
token:   { enabled: true,  role: { name: token,   configKey: token,   ports: [ { name: xrootd, port: 11097 } ], data: { root: /data/xrootd } } }
webdav:  { enabled: true,  role: { name: webdav,  configKey: webdav,  ports: [ { name: https,  port: 8443 } ],  data: { root: /data/xrootd } } }
s3:      { enabled: false, role: { name: s3,      configKey: s3,      ports: [ { name: http,   port: 9001 } ],  data: { root: /data/xrootd } } }
metrics: { enabled: true,  role: { name: metrics, configKey: metrics, ports: [ { name: http,   port: 9100 } ],  data: { root: /data/xrootd } } }
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/main-fleet && helm unittest k8s-tests/charts/main-fleet` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: `topology-role` — mount CA bundle + run the fetch sidecar for auth roles

**Files:**
- Modify: `k8s-tests/charts/topology-role/templates/deployment.yaml`
- Modify: `k8s-tests/charts/topology-role/values.yaml` (add `role.auth`)
- Create: `k8s-tests/charts/topology-role/tests/auth_mounts_test.yaml`

**Interfaces:**
- Consumes: `.Values.role.auth` = `{ caBundle: <configmap>, hostCertSecret: <secret>, crlUrl: <url>, jwksUrl: <url> }` (all optional).
- Produces: when set, mounts the CA bundle ConfigMap at `/etc/grid-security/certificates`, the host cert/key Secret at `/etc/grid-security`, and adds `brix-common.fetchSidecar` container(s) writing CRL→`/etc/brix/crl/crl.pem` and JWKS→`/etc/brix/jwks/jwks.json` on shared `emptyDir`s.

- [ ] **Step 1: Write the failing test** `tests/auth_mounts_test.yaml`:
```yaml
suite: role auth mounts
templates: [templates/deployment.yaml]
release: { name: brix-fleet }
tests:
  - it: mounts CA bundle and adds a CRL fetch sidecar when configured
    set:
      role:
        name: gsi
        ports: [ { name: xrootd, port: 11095 } ]
        auth:
          caBundle: brix-fleet-ca-bundle
          hostCertSecret: brix-fleet-pki
          crlUrl: http://brix-fleet-grid-ca:8080/crl/test-user.crl.pem
    asserts:
      - contains:
          path: spec.template.spec.volumes
          content: { name: cacerts, configMap: { name: brix-fleet-ca-bundle } }
      - matchRegex:
          path: spec.template.spec.containers[1].args[0]
          pattern: "curl .*grid-ca:8080/crl.*-o /etc/brix/crl/crl.pem"
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** Extend `deployment.yaml` — after the main container, append fetch sidecars and extra volumes/mounts guarded by `.Values.role.auth`:
```yaml
        {{- if and .Values.role.auth .Values.role.auth.crlUrl }}
        - {{ include "brix-common.fetchSidecar" (dict "name" "crl-refresh" "url" .Values.role.auth.crlUrl "dest" "/etc/brix/crl/crl.pem" "interval" 30 "volumeName" "crl") | nindent 10 | trim }}
        {{- end }}
        {{- if and .Values.role.auth .Values.role.auth.jwksUrl }}
        - {{ include "brix-common.fetchSidecar" (dict "name" "jwks-refresh" "url" .Values.role.auth.jwksUrl "dest" "/etc/brix/jwks/jwks.json" "interval" 15 "volumeName" "jwks") | nindent 10 | trim }}
        {{- end }}
```
Add the corresponding mounts to the main container and volumes:
```yaml
          {{- if .Values.role.auth }}
            {{- if .Values.role.auth.caBundle }}
            - { name: cacerts, mountPath: /etc/grid-security/certificates, readOnly: true }
            {{- end }}
            {{- if .Values.role.auth.hostCertSecret }}
            - { name: hostpki, mountPath: /etc/grid-security, readOnly: true }
            {{- end }}
            {{- if .Values.role.auth.crlUrl }}
            - { name: crl, mountPath: /etc/brix/crl }
            {{- end }}
            {{- if .Values.role.auth.jwksUrl }}
            - { name: jwks, mountPath: /etc/brix/jwks }
            {{- end }}
          {{- end }}
```
and volumes:
```yaml
        {{- if .Values.role.auth }}
        {{- if .Values.role.auth.caBundle }}
        - { name: cacerts, configMap: { name: {{ .Values.role.auth.caBundle }} } }
        {{- end }}
        {{- if .Values.role.auth.hostCertSecret }}
        - name: hostpki
          secret:
            secretName: {{ .Values.role.auth.hostCertSecret }}
            items:
              - { key: hostcert.pem, path: hostcert.pem }
              - { key: hostkey.pem,  path: hostkey.pem }
        {{- end }}
        {{- if .Values.role.auth.crlUrl }}
        - { name: crl,  emptyDir: {} }
        {{- end }}
        {{- if .Values.role.auth.jwksUrl }}
        - { name: jwks, emptyDir: {} }
        {{- end }}
        {{- end }}
```
Note: an nginx-xrootd server that reads a JWKS/CRL file at startup needs the file present before it starts; add an initContainer that does a single fetch (reuse fetchSidecar logic once) so the file exists on boot, with the sidecar keeping it fresh. Add that initContainer under the same `auth.jwksUrl`/`auth.crlUrl` guards.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/topology-role` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 4: Wire fleet auth roles to the #1 authorities via values

**Files:**
- Modify: `k8s-tests/charts/main-fleet/values.yaml` (add `role.auth` to gsi/tls/token/webdav)
- Create: `k8s-tests/charts/main-fleet/tests/auth_consume_test.yaml`

**Interfaces:**
- Produces: gsi/tls carry `auth.caBundle` + `auth.hostCertSecret` + `auth.crlUrl`; token/webdav carry `auth.jwksUrl` (+ CA for webdav). The `<rel>-*` names resolve at umbrella install where release is `brix-fleet` and authorities install into the same namespace.

- [ ] **Step 1: Write the failing test** `tests/auth_consume_test.yaml`:
```yaml
suite: fleet consumes authorities
templates: [charts/token/charts/topology-role/templates/deployment.yaml]
release: { name: brix-fleet }
tests:
  - it: token role fetches JWKS from the issuer service
    asserts:
      - matchRegex:
          path: spec.template.spec.containers[1].args[0]
          pattern: "token-issuer:8080/certs/jwks.json"
```
(If the nested subchart-of-subchart template path is awkward in helm-unittest, assert instead by rendering `main-fleet` with `helm template` in Step 4 and grepping.)

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** In `main-fleet/values.yaml`, extend the auth roles (using the fixed authority Service names for release `brix-fleet`):
```yaml
gsi:
  enabled: true
  role:
    name: gsi
    configKey: gsi
    ports: [ { name: xrootd, port: 11095 } ]
    data: { root: /data/xrootd }
    auth:
      caBundle: brix-fleet-ca-bundle
      hostCertSecret: brix-fleet-pki
      crlUrl: http://brix-fleet-grid-ca:8080/crl/test-user.crl.pem
token:
  enabled: true
  role:
    name: token
    configKey: token
    ports: [ { name: xrootd, port: 11097 } ]
    data: { root: /data/xrootd }
    auth:
      jwksUrl: http://brix-fleet-token-issuer:8080/certs/jwks.json
```
(webdav gets both caBundle + jwksUrl + hostCertSecret; tls mirrors gsi.) Because these names hardcode the release `brix-fleet`, document that the fleet profile installs with `--set global.releaseName` or simply always deploys as release `brix-fleet` (the `xrd-lab deploy fleet` convention pins release `brix-fleet`). Prefer templating the authority host from a shared value: add `global.authRelease: brix-fleet` and reference `{{ .Values.global.authRelease }}-token-issuer` — but cross-subchart `global` is the clean Helm mechanism. **Decision:** use Helm `global.authRelease` and update `topology-role` auth URLs to accept a pre-rendered string (they already do — the URL is passed whole from values). Keep the values literal `brix-fleet-*` and pin the release name in `xrd-lab` (`helm upgrade --install brix-fleet ...`).

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/main-fleet && helm template brix-fleet k8s-tests/charts/main-fleet | grep 'token-issuer:8080/certs/jwks.json'` → matches; `helm unittest` green.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 5: Reference stock-XRootD role

**Files:**
- Create: `k8s-tests/images/xrootd-reference/Dockerfile` (adapt existing `k8s-tests/Dockerfiles/xrootd-reference/`)
- Create: `k8s-tests/charts/main-fleet/templates/reference.yaml`
- Add suite `k8s-tests/charts/main-fleet/tests/reference_test.yaml`

**Interfaces:**
- Produces image `brix-xrootd-ref:dev` (stock xrootd, anon config on 11098) and a Deployment+Service `<rel>-reference`.

- [ ] **Step 1: Write the failing test** `tests/reference_test.yaml`:
```yaml
suite: reference xrootd
templates: [templates/reference.yaml]
release: { name: brix-fleet }
tests:
  - it: renders a reference Service on 11098 when enabled
    set: { reference: { enabled: true } }
    documentIndex: 1
    asserts:
      - equal: { path: spec.ports[0].port, value: 11098 }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write** the Dockerfile (reuse existing xrootd-reference `entrypoint.sh` + `xrootd-anon.cf`) and `templates/reference.yaml` (a standard Deployment+Service using `brix-common` labels, image `brix-xrootd-ref:dev`, guarded by `.Values.reference.enabled`). Add `reference: { enabled: true }` to values.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/main-fleet` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 6: `test-runner` — tiers, JUnit, results PVC

**Files:**
- Modify: `k8s-tests/charts/test-runner/templates/job.yaml`
- Modify: `k8s-tests/charts/test-runner/values.yaml`
- Create: `k8s-tests/charts/test-runner/tests/tier_test.yaml`

**Interfaces:**
- Consumes: `.Values.testRunner.tier` (`fast`|`pr`|`nightly`|`custom`), `.Values.testRunner.marker`, `.Values.testRunner.junit` (bool), `.Values.results.pvc` (name).
- Produces: a Job whose pytest args map the tier to markers (`fast`→`-m "not slow and not serial"`, `pr`→`-m "not slow"`, `nightly`→`-m slow`) and write `--junitxml=/results/<tier>.xml` to a mounted results PVC.

- [ ] **Step 1: Write the failing test** `tests/tier_test.yaml`:
```yaml
suite: test-runner tiers
templates: [templates/job.yaml]
release: { name: brix-fleet }
tests:
  - it: fast tier selects non-slow non-serial and writes junit
    set: { testRunner: { tier: fast, junit: true }, results: { pvc: brix-fleet-results } }
    asserts:
      - matchRegex: { path: spec.template.spec.containers[0].args[0], pattern: '-m "not slow and not serial"' }
      - matchRegex: { path: spec.template.spec.containers[0].args[0], pattern: "--junitxml=/results/fast.xml" }
      - contains:
          path: spec.template.spec.volumes
          content: { name: results, persistentVolumeClaim: { claimName: brix-fleet-results } }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** Extend `values.yaml`:
```yaml
testRunner:
  tier: fast          # fast | pr | nightly | custom
  selection: tests/
  marker: ""
  extraArgs: "-p no:xdist -v"
  junit: true
  env: {}
results:
  pvc: ""
```
Rewrite the args in `job.yaml`:
```yaml
          args:
            - |
              {{- $marker := "" }}
              {{- if eq .Values.testRunner.tier "fast" }}{{ $marker = "not slow and not serial" }}{{- end }}
              {{- if eq .Values.testRunner.tier "pr" }}{{ $marker = "not slow" }}{{- end }}
              {{- if eq .Values.testRunner.tier "nightly" }}{{ $marker = "slow" }}{{- end }}
              {{- if eq .Values.testRunner.tier "custom" }}{{ $marker = .Values.testRunner.marker }}{{- end }}
              pytest {{ .Values.testRunner.selection }} \
                {{- if $marker }} -m "{{ $marker }}"{{- end }} \
                {{- if .Values.testRunner.junit }} --junitxml=/results/{{ .Values.testRunner.tier }}.xml{{- end }} \
                {{ .Values.testRunner.extraArgs }}
```
Add results volume/mount guarded by `.Values.results.pvc`:
```yaml
          {{- if .Values.results.pvc }}
          volumeMounts: [ { name: results, mountPath: /results } ]
          {{- end }}
      {{- if .Values.results.pvc }}
      volumes: [ { name: results, persistentVolumeClaim: { claimName: {{ .Values.results.pvc }} } } ]
      {{- end }}
```
Add a `templates/results-pvc.yaml` (guarded by `.Values.results.create`) that creates the PVC.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/test-runner` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 7: Fleet profiles + live e2e (fast tier)

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `main-fleet` dep, conditioned)
- Create: `k8s-tests/charts/brix-test-lab/values/values.fleet.yaml`, `values.fleet-fast.yaml`
- Modify: `k8s-tests/xrd-lab` (build fleet+ref+runner images; `test fleet-fast` scenario)
- Create: `k8s-tests/tests-bats/fleet_e2e.bats`
- Delete: `k8s-tests/server-helm/` (retired — superseded by `main-fleet`)

**Interfaces:**
- Produces: `xrd-lab deploy fleet` (release pinned `brix-fleet`) brings up authorities + fleet; `xrd-lab test fleet-fast` runs the fast tier and reports pass/fail + writes JUnit to the results PVC.

- [ ] **Step 1: Write the failing test** `tests-bats/fleet_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] || skip; "$LAB" up; "$LAB" deploy fleet; }
teardown_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] && "$LAB" down fleet || true; }

@test "anon root:// round-trip works in-cluster" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  run "$LAB" test fleet-smoke      # a tiny xrdcp put/get against the anon Service
  [ "$status" -eq 0 ]
  [[ "$output" == *"fleet OK"* ]]
}

@test "dry-run fleet-fast launches the fast-tier runner" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test fleet-fast
  [ "$status" -eq 0 ]
  [[ "$output" == *"tier=fast"* || "$output" == *"testRunner.tier=fast"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Umbrella dep:
```yaml
  - { name: main-fleet, version: 0.1.0, repository: file://../main-fleet, condition: main-fleet.enabled }
```
`values/values.fleet.yaml`:
```yaml
auth-authority: { enabled: true, services: { ca: true, token: true, voms: true, krb5: false } }
main-fleet: { enabled: true }
smoke: { enabled: false }
```
`values/values.fleet-fast.yaml` = `values.fleet.yaml` (the fast tier is launched on demand by `xrd-lab test fleet-fast`, not at deploy). Add `xrd-lab` scenarios `fleet-smoke` (ephemeral xrdcp put/get against `brix-fleet-anon:11094`) and `fleet-fast` (helm-install the test-runner with `testRunner.tier=fast`, `TEST_SERVER_HOST=brix-fleet-anon` + per-role `TEST_*_HOST/PORT` env, `results.pvc=brix-fleet-results`, wait for Job, print summary). Pin the fleet release to `brix-fleet` in `cmd_deploy` when profile==fleet.

Remove the legacy chart:
```bash
rm -rf k8s-tests/server-helm
```

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/fleet_e2e.bats     # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
helm dependency build k8s-tests/charts/brix-test-lab
helm template brix-fleet k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.fleet.yaml | kubeconform -strict -summary
```
Then live:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/fleet_e2e.bats
# and the fast tier (longer):
XRD_LAB_E2E=1 XRD_LAB_NODES=1 bash -c '"'"$PWD"'/k8s-tests/xrd-lab" up && k8s-tests/xrd-lab deploy fleet && k8s-tests/xrd-lab test fleet-fast'
```
Expected: `fleet OK`; the fast-tier Job completes and JUnit `fast.xml` lands on the results PVC. Some fast tests assume localhost-only behaviour; triage per spec §7 — fixes are narrow env-surface additions in `settings.py`, not suite rewrites.

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #3)

- [ ] `helm unittest` green for `main-fleet`, `topology-role`, `test-runner`.
- [ ] `helm template brix-fleet ... -f values.fleet.yaml | kubeconform -strict -summary` → `Invalid: 0`.
- [ ] `XRD_LAB_E2E=1 bats k8s-tests/tests-bats/fleet_e2e.bats` → `fleet OK`.
- [ ] Fast tier Job completes; `fast.xml` present on the results PVC; failures triaged.
- [ ] `k8s-tests/server-helm` removed.
- [ ] **DoD (spec §5 row 3):** the `--fast` tier of the real suite runs in-cluster with JUnit collected. ✅ when the fast-tier Job completes and results are collected.

## Self-review notes

- **Spec coverage:** §4.4 fleet roles → Tasks 1,2,5; authority consumption (CA mount + CRL/JWKS fetch) → Tasks 3,4; test-runner tiers + JUnit + results → Task 6; profiles + fast-tier gate → Task 7; legacy `server-helm` retirement → Task 7.
- **Placeholder scan:** the `global.authRelease` vs pinned-release decision is resolved (pin release `brix-fleet`); the nested-subchart unit-test path caveat has a stated fallback (grep `helm template`). No TODOs.
- **Name consistency:** `brix_*` directive names match `nginx_shared.conf`; authority Service names (`brix-fleet-grid-ca`, `brix-fleet-token-issuer`) and Secret/ConfigMap contract (`brix-fleet-ca-bundle`, `brix-fleet-pki`) match #1's Task 3 contract with release `brix-fleet`; `topology-role.auth` shape defined in Task 3 used identically in Task 4; tier→marker mapping matches `tests/run_suite.sh`.
