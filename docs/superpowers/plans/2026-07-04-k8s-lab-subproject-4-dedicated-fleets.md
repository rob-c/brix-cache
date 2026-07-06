# K8s Test Lab — Sub-project #4: Dedicated Behavior-Fleet Catalog — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Checkbox (`- [ ]`) steps. **No git commands** — "Checkpoint (no git)" is a verification gate.

**Goal:** Convert the ~89 dedicated fixed-config nginx test fleets (`tests/lib/dedicated.sh`) into a **data-driven scenario catalog** rendered through the existing `topology-role` chart, so any dedicated scenario is a one-liner `xrd-lab test <scenario>` on demand — no bespoke manifests.

**Architecture:** A `scenarios/catalog.yaml` maps each scenario name → its config template (an existing `tests/configs/nginx_*.conf`), ports, auth material, upstream/backend refs, and the pytest module(s) that exercise it. A small `dedicated` subchart instantiates one (or a few) `topology-role`(s) from a selected catalog entry; `xrd-lab test <scenario>` deploys it, runs the mapped tests via `test-runner`, and tears down. Depends on #0, #1, #2 (`topology-role`, `test-runner`, `brix-server`), and #3 (auth-consumption plumbing on `topology-role`).

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, yq, pytest.

**Spec:** §4.5. **Dependencies:** #0, #1, #2, #3.

## Global Constraints

- Inherits all #0 constraints.
- **Catalog is the single source of truth** for dedicated scenarios; no per-scenario templates. Adding a scenario = one `catalog.yaml` entry + (if new) copying its config into `topology-role/configs/`.
- **Configs are the repo's real `tests/configs/nginx_*.conf`**, adapted only for Helm port/DNS/mount substitution (same mechanical transform as #2 Task 3). `brix_*` directives, unchanged semantics.
- **Tests run unmodified**, env-wired to the scenario's Service DNS/ports.

## Representative catalog coverage (from `tests/lib/dedicated.sh`)

The 89 fleets cluster into families; the catalog covers all, and the DoD verifies a representative set:

| Scenario | Config | Ports | Notes / test module |
|---|---|---|---|
| `readonly` | `nginx_readonly.conf` | 11102 | read-only gate → `test_readonly*.py` |
| `vo-acl` | `nginx_vo_acl.conf` | 11103 | VO ACL → `test_vo_acl*.py` (needs CA/VOMS from #1) |
| `crl` | `nginx_crl.conf` | 11104/8443 | GSI + CRL → `test_crl*.py` (fetch sidecar) |
| `tpc-ssrf-default` | `nginx_tpc_ssrf_default.conf` | 11180 | SSRF guard → `test_tpc_ssrf*.py` |
| `s3-presigned` | `nginx_s3_presigned.conf` | 11183 | S3 presign → `test_s3_presigned*.py` |
| `security-level-pedantic` | `nginx_security_level_pedantic.conf` | 11192 | sec levels → `test_security_level*.py` |
| `ipv6-stream` | `nginx_ipv6_stream.conf` | 11240 | IPv6 → `test_ipv6*.py` (needs IPv6-enabled cluster) |
| `webdav-voms` | `nginx_webdav_voms.conf` | 18458 | GSI+VOMS webdav → `test_webdav_voms*.py` |

---

## File Structure

```
k8s-tests/
├── scenarios/
│   ├── catalog.yaml                             # name -> {config, ports, auth, upstreams, tests} (Task 1)
│   └── schema.md                                # documented catalog schema (Task 1)
├── charts/dedicated/
│   ├── Chart.yaml                               # dependency: topology-role + test-runner
│   ├── values.yaml                              # a single scenario's rendered role values
│   ├── templates/role.yaml                      # thin wrapper feeding topology-role from values
│   └── tests/scenario_test.yaml
├── charts/topology-role/configs/                # + any dedicated configs not already present (Task 2)
├── tools/
│   ├── catalog-lint.sh                          # validates catalog.yaml against configs + schema (Task 1)
│   └── scenario-render.sh                       # yq: catalog entry -> helm --set args (Task 3)
└── tests-bats/
    ├── catalog.bats                             # Task 1
    ├── scenario_render.bats                     # Task 3
    └── dedicated_e2e.bats                        # Task 4 (opt-in live)
```

---

## Task 1: Scenario catalog + schema + linter

**Files:**
- Create: `k8s-tests/scenarios/catalog.yaml`
- Create: `k8s-tests/scenarios/schema.md`
- Create: `k8s-tests/tools/catalog-lint.sh`
- Create: `k8s-tests/tests-bats/catalog.bats`

**Interfaces:**
- Produces: `catalog.yaml` — a map `scenarios: { <name>: { configKey, ports: [{name,port}], auth: {...}, upstreams: [...], tests: "<pytest selection>", env: {...} } }`. `catalog-lint.sh` exits non-zero if any entry references a `configKey` with no `topology-role/configs/<key>.conf`, or a duplicate port within a scenario.

- [ ] **Step 1: Write the failing test** `k8s-tests/tests-bats/catalog.bats`:
```bash
#!/usr/bin/env bats
ROOT="${BATS_TEST_DIRNAME}/.."
LINT="$ROOT/tools/catalog-lint.sh"

@test "catalog lints clean" {
  run bash "$LINT" "$ROOT/scenarios/catalog.yaml"
  [ "$status" -eq 0 ]
}

@test "linter rejects a scenario whose configKey has no config file" {
  tmp="$BATS_TEST_TMPDIR/bad.yaml"
  printf 'scenarios:\n  bogus:\n    configKey: does_not_exist\n    ports: [{name: x, port: 1}]\n    tests: tests/test_x.py\n' > "$tmp"
  run bash "$LINT" "$tmp"
  [ "$status" -ne 0 ]
  [[ "$output" == *"does_not_exist"* ]]
}

@test "known scenarios are present" {
  for s in readonly crl tpc-ssrf-default s3-presigned webdav-voms; do
    yq -e ".scenarios.\"$s\"" "$ROOT/scenarios/catalog.yaml" >/dev/null
  done
}
```

- [ ] **Step 2: Run** `bats k8s-tests/tests-bats/catalog.bats` → FAIL (files absent).

- [ ] **Step 3: Write.** `scenarios/schema.md` documents the fields. `scenarios/catalog.yaml` (seed with the representative set; extend to all 89 incrementally):
```yaml
scenarios:
  readonly:
    configKey: readonly
    ports: [{ name: xrootd, port: 11102 }]
    tests: tests/test_readonly.py
    env: { TEST_SERVER_HOST: SCENARIO_SVC, TEST_READONLY_PORT: "11102" }
  crl:
    configKey: crl
    ports: [{ name: xrootd, port: 11104 }, { name: webdav, port: 8443 }]
    auth: { caBundle: CA_BUNDLE, hostCertSecret: PKI_SECRET, crlUrl: CRL_URL }
    tests: tests/test_crl.py
    env: { TEST_SERVER_HOST: SCENARIO_SVC, TEST_CRL_PORT: "11104" }
  tpc-ssrf-default:
    configKey: tpc_ssrf_default
    ports: [{ name: webdav, port: 11180 }]
    tests: tests/test_tpc_ssrf.py
    env: { TEST_SERVER_HOST: SCENARIO_SVC, TPC_SSRF_DEFAULT_PORT: "11180" }
  s3-presigned:
    configKey: s3_presigned
    ports: [{ name: http, port: 11183 }]
    tests: tests/test_s3_presigned.py
    env: { TEST_SERVER_HOST: SCENARIO_SVC, S3_PRESIGNED_PORT: "11183" }
  webdav-voms:
    configKey: webdav_voms
    ports: [{ name: https, port: 18458 }]
    auth: { caBundle: CA_BUNDLE, hostCertSecret: PKI_SECRET, vomsdir: VOMSDIR_CM }
    tests: tests/test_webdav_voms.py
    env: { TEST_SERVER_HOST: SCENARIO_SVC, NGINX_WEBDAV_VOMS_PORT: "18458" }
```
(The literal tokens `SCENARIO_SVC`, `CA_BUNDLE`, `PKI_SECRET`, `CRL_URL`, `VOMSDIR_CM` are placeholders substituted at deploy time by `scenario-render.sh` — Task 3.)

`tools/catalog-lint.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
CATALOG="${1:?usage: catalog-lint.sh <catalog.yaml>}"
CONFIG_DIR="$(cd "$(dirname "$0")/.." && pwd)/charts/topology-role/configs"
rc=0
for name in $(yq -r '.scenarios | keys[]' "$CATALOG"); do
    key="$(yq -r ".scenarios.\"$name\".configKey" "$CATALOG")"
    if [ ! -f "$CONFIG_DIR/$key.conf" ]; then
        echo "MISSING CONFIG: scenario '$name' -> $key.conf (looked in $CONFIG_DIR)" >&2
        rc=1
    fi
    # duplicate-port check
    dups="$(yq -r ".scenarios.\"$name\".ports[].port" "$CATALOG" | sort | uniq -d)"
    if [ -n "$dups" ]; then
        echo "DUP PORT: scenario '$name' repeats port(s): $dups" >&2
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "catalog OK"
exit "$rc"
```

- [ ] **Step 4: Copy the referenced configs (Task 2 does the bulk); for this task, ensure at least the representative configKeys exist** so the linter passes — see Task 2. Run `bats k8s-tests/tests-bats/catalog.bats` after Task 2 → PASS. (Order note: Task 1 test 1 depends on Task 2's configs; run Task 2 first, then re-run this suite.)

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 2: Import the dedicated configs into `topology-role/configs/`

**Files:**
- Create: `k8s-tests/charts/topology-role/configs/{readonly,crl,tpc_ssrf_default,s3_presigned,webdav_voms,...}.conf`
- Create: `k8s-tests/charts/topology-role/tests/dedicated_configs_test.yaml`

**Interfaces:**
- Produces: each dedicated config, mechanically transformed from `tests/configs/nginx_<name>.conf` (sed markers → Helm expressions), consuming auth mount paths identical to #3 (`/etc/grid-security/...`, `/etc/brix/crl/crl.pem`).

- [ ] **Step 1: Write the failing test** `tests/dedicated_configs_test.yaml`:
```yaml
suite: dedicated configs render
templates: [templates/configmap.yaml]
release: { name: brix-scn }
tests:
  - it: crl config uses gsi + mounted crl file
    set: { role: { name: crl, configKey: crl, ports: [{ name: xrootd, port: 11104 }], data: { root: /data/xrootd } } }
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_auth gsi" }
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_crl /etc/brix/crl/crl.pem" }
  - it: tpc-ssrf config renders on its port
    set: { role: { name: tpc, configKey: tpc_ssrf_default, ports: [{ name: http, port: 11180 }], data: { root: /data/xrootd } } }
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "listen 11180" }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** For each scenario config, copy the real `tests/configs/nginx_<x>.conf` and apply the mechanical transform:
  - `{PORT}`/`{ANON_PORT}`/etc. → `{{ (index .Values.role.ports N).port }}`
  - `{DATA_DIR}` → `{{ .Values.role.data.root }}`
  - `{LOG_DIR}/...` → fixed `/var/log/brix/...`
  - `{SERVER_CERT}` → `/etc/grid-security/hostcert.pem`; `{SERVER_KEY}` → `/etc/grid-security/hostkey.pem`; `{CA_CERT}` → `/etc/grid-security/certificates/ca.pem`; `{CRL_PATH}` → `/etc/brix/crl/crl.pem`; `{VOMSDIR}` → `/etc/grid-security/vomsdir`; `{CA_DIR}` → `/etc/grid-security/certificates`
  - upstream markers → `{{ .Release.Name }}-{{ (index .Values.role.upstreams N).service }}:{{ ...port }}`

Example `configs/crl.conf` (from `nginx_crl.conf`, verified content):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log info;
thread_pool default threads=4 max_queue=65536;
events { worker_connections 64; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    brix_root on;
    brix_storage_backend posix:{{ .Values.role.data.root }};
    brix_auth gsi;
    brix_allow_write on;
    brix_certificate     /etc/grid-security/hostcert.pem;
    brix_certificate_key /etc/grid-security/hostkey.pem;
    brix_trusted_ca      /etc/grid-security/certificates/ca.pem;
    brix_crl             /etc/brix/crl/crl.pem;
  }
}
http {
  server {
    listen {{ (index .Values.role.ports 1).port }} ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;
    ssl_verify_client   optional_no_ca;
    brix_webdav_proxy_certs on;
    location / {
      brix_webdav on;
      brix_storage_backend posix:{{ .Values.role.data.root }};
      brix_webdav_cafile /etc/grid-security/certificates/ca.pem;
      brix_webdav_crl    /etc/brix/crl/crl.pem;
      brix_webdav_auth   required;
      brix_allow_write on;
    }
  }
}
```
Repeat for `readonly`, `tpc_ssrf_default`, `s3_presigned`, `webdav_voms`, then extend to the remaining families. Provide a helper `tools/import-config.sh <name>` that applies the sed→Helm transform for the bulk import (optional convenience, not required by tests).

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/topology-role -f tests/dedicated_configs_test.yaml` → PASS; then re-run `bats k8s-tests/tests-bats/catalog.bats` (now that configs exist) → PASS.

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: `scenario-render.sh` — catalog entry → helm values

**Files:**
- Create: `k8s-tests/tools/scenario-render.sh`
- Create: `k8s-tests/charts/dedicated/Chart.yaml`, `values.yaml`, `templates/role.yaml`, `tests/scenario_test.yaml`
- Create: `k8s-tests/tests-bats/scenario_render.bats`

**Interfaces:**
- Produces: `scenario-render.sh <catalog> <name> <release> <namespace>` emits the `--set` argument list (or a values YAML) for `helm upgrade --install` of the `dedicated` chart, resolving the placeholder tokens (`SCENARIO_SVC`→`<release>-<name>`, `CA_BUNDLE`→`<release>-ca-bundle`, `CRL_URL`→`http://<release>-grid-ca:8080/crl/test-user.crl.pem`, `PKI_SECRET`→`<release>-pki`, `VOMSDIR_CM`→`<release>-vomsdir`).

- [ ] **Step 1: Write the failing test** `tests-bats/scenario_render.bats`:
```bash
#!/usr/bin/env bats
ROOT="${BATS_TEST_DIRNAME}/.."
REND="$ROOT/tools/scenario-render.sh"

@test "renders crl scenario with resolved CA/CRL and service name" {
  run bash "$REND" "$ROOT/scenarios/catalog.yaml" crl brix-scn brix-dedicated
  [ "$status" -eq 0 ]
  [[ "$output" == *"role.name=crl"* ]]
  [[ "$output" == *"role.configKey=crl"* ]]
  [[ "$output" == *"role.auth.crlUrl=http://brix-scn-grid-ca:8080/crl/test-user.crl.pem"* ]]
  [[ "$output" == *"role.auth.caBundle=brix-scn-ca-bundle"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** `charts/dedicated/Chart.yaml` depends on `topology-role`; `templates/role.yaml` is a thin pass-through (the `dedicated` chart *is* a single `topology-role` fed by values — simplest is to alias `topology-role` as a dependency and let `values.yaml` set `.role`). `values.yaml` has an empty `role: {}`. 

`tools/scenario-render.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
CATALOG="${1:?catalog}"; NAME="${2:?scenario}"; REL="${3:?release}"; NS="${4:?namespace}"
q() { yq -r "$1" "$CATALOG"; }
key="$(q ".scenarios.\"$NAME\".configKey")"
echo "--set role.name=$NAME"
echo "--set role.configKey=$key"
i=0
for p in $(q ".scenarios.\"$NAME\".ports[].port"); do
    n="$(q ".scenarios.\"$NAME\".ports[$i].name")"
    echo "--set role.ports[$i].name=$n --set role.ports[$i].port=$p"
    i=$((i+1))
done
# resolve auth placeholders if present
resolve() { sed -e "s|SCENARIO_SVC|$REL-$NAME|g" -e "s|CA_BUNDLE|$REL-ca-bundle|g" \
                -e "s|PKI_SECRET|$REL-pki|g" -e "s|VOMSDIR_CM|$REL-vomsdir|g" \
                -e "s|CRL_URL|http://$REL-grid-ca:8080/crl/test-user.crl.pem|g" \
                -e "s|JWKS_URL|http://$REL-token-issuer:8080/certs/jwks.json|g"; }
if [ "$(q ".scenarios.\"$NAME\" | has(\"auth\")")" = "true" ]; then
    for k in $(q ".scenarios.\"$NAME\".auth | keys[]"); do
        v="$(q ".scenarios.\"$NAME\".auth.$k" | resolve)"
        echo "--set role.auth.$k=$v"
    done
fi
```

- [ ] **Step 4: Run** `bats k8s-tests/tests-bats/scenario_render.bats` → PASS; `shellcheck k8s-tests/tools/scenario-render.sh k8s-tests/tools/catalog-lint.sh` → clean.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 4: `xrd-lab test <scenario>` + live e2e

**Files:**
- Modify: `k8s-tests/xrd-lab` (generic `scenario_dedicated` path driven by the catalog)
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `dedicated` dep, conditioned) OR install the `dedicated` chart directly from `xrd-lab` (preferred — scenarios are on-demand, not a profile)
- Create: `k8s-tests/tests-bats/dedicated_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab test <scenario>` = deploy authorities (if the scenario's `auth` needs them) + the `dedicated` chart via rendered values, run the mapped pytest via `test-runner`, report status, tear the scenario down.

- [ ] **Step 1: Write the failing test** `tests-bats/dedicated_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] || skip; "$LAB" up; }
teardown_file() { :; }

@test "readonly scenario passes end to end" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  run "$LAB" test readonly
  [ "$status" -eq 0 ]
  [[ "$output" == *"passed"* ]]
}

@test "dry-run scenario prints catalog-resolved helm install + pytest" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test readonly
  [ "$status" -eq 0 ]
  [[ "$output" == *"role.configKey=readonly"* ]]
  [[ "$output" == *"test_readonly.py"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement `scenario_dedicated` in `xrd-lab`.** In `cmd_test`, before the explicit cases (`smoke|chaos|authorities|fleet-*`), add a fallthrough: if `$scenario` is a key in `scenarios/catalog.yaml`, dispatch to `scenario_dedicated "$scenario"`:
```bash
scenario_dedicated() {
    local name="$1" ns="brix-dedicated" rel="brix-dedicated"
    local catalog="$LAB_DIR/scenarios/catalog.yaml"
    local tests; tests="$(yq -r ".scenarios.\"$name\".tests" "$catalog")"
    local needs_auth; needs_auth="$(yq -r ".scenarios.\"$name\" | has(\"auth\")" "$catalog")"
    local sets; sets="$(bash "$LAB_DIR/tools/scenario-render.sh" "$catalog" "$name" "$rel" "$ns")"
    if [ "$DRY_RUN" = "1" ]; then
        echo "helm upgrade --install $rel charts/dedicated --namespace $ns $sets"
        echo "pytest $tests (via test-runner)"
        return 0
    fi
    [ "$needs_auth" = "true" ] && run helm upgrade --install "$rel-auth" "$LAB_DIR/charts/auth-authority" --namespace "$ns" --create-namespace --set services.ca=true,services.voms=true
    # shellcheck disable=SC2086
    helm upgrade --install "$rel" "$LAB_DIR/charts/dedicated" --namespace "$ns" --create-namespace $sets --wait --timeout 5m
    helm upgrade --install "$rel-run" "$LAB_DIR/charts/test-runner" --namespace "$ns" \
        --set image.repository=brix-test-runner,image.tag=dev \
        --set testRunner.selection="$tests" \
        --set testRunner.env.TEST_SERVER_HOST="$rel-$name"
    kubectl -n "$ns" wait --for=condition=complete --timeout=300s "job/$rel-run-test-runner" || true
    kubectl -n "$ns" logs "job/$rel-run-test-runner"
    local ok; ok="$(kubectl -n "$ns" get job "$rel-run-test-runner" -o jsonpath='{.status.succeeded}')"
    helm uninstall "$rel" "$rel-run" -n "$ns" >/dev/null 2>&1 || true
    [ "$ok" = "1" ]
}
```
Wire the fallthrough in `cmd_test`'s `case` default: `*) if yq -e ".scenarios.\"$scenario\"" "$LAB_DIR/scenarios/catalog.yaml" >/dev/null 2>&1; then scenario_dedicated "$scenario"; else echo "unknown scenario" >&2; return 2; fi ;;`

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/dedicated_e2e.bats     # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
```
Then live (representative set):
```bash
XRD_LAB_E2E=1 bash -c 'k8s-tests/xrd-lab up; for s in readonly tpc-ssrf-default s3-presigned; do k8s-tests/xrd-lab test "$s" || exit 1; done'
```
Expected: each scenario's mapped tests pass (`passed`). `crl`/`webdav-voms` additionally require the authorities (auto-installed by `scenario_dedicated`).

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 5: Backfill the remaining catalog entries

**Files:**
- Modify: `k8s-tests/scenarios/catalog.yaml` (all remaining dedicated fleets)
- Modify: `k8s-tests/charts/topology-role/configs/` (any not yet imported)

**Interfaces:** none new — this extends the data set covered by Tasks 1–4.

- [ ] **Step 1:** Enumerate every `start_dedicated_nginx "<name>" "<config>" "<port>"` in `tests/lib/dedicated.sh`; for each, add a `catalog.yaml` entry (configKey = config basename sans `nginx_`/`.conf`; port from the call; `tests` = the module(s) that reference that port in `tests/settings.py`). Import any missing config via the Task 2 transform.
- [ ] **Step 2:** Run `bash k8s-tests/tools/catalog-lint.sh k8s-tests/scenarios/catalog.yaml` → `catalog OK` (every configKey resolves).
- [ ] **Step 3:** Spot-render 5 random scenarios: `for s in $(yq -r '.scenarios|keys[]' scenarios/catalog.yaml | shuf | head -5); do bash tools/scenario-render.sh scenarios/catalog.yaml "$s" r ns; done` → all succeed.
- [ ] **Step 4:** `helm template` a couple of scenario configs through `topology-role` → `kubeconform -strict` clean.
- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #4)

- [ ] `bash k8s-tests/tools/catalog-lint.sh k8s-tests/scenarios/catalog.yaml` → `catalog OK` for all entries.
- [ ] `bats k8s-tests/tests-bats/catalog.bats k8s-tests/tests-bats/scenario_render.bats` → PASS.
- [ ] `helm unittest k8s-tests/charts/topology-role` → PASS (dedicated config suites).
- [ ] `XRD_LAB_E2E=1` representative set (`readonly`, `tpc-ssrf-default`, `s3-presigned`, `crl`, `webdav-voms`) → each passes.
- [ ] **DoD (spec §5 row 4):** a representative set of dedicated scenarios passes on demand via the catalog. ✅

## Self-review notes

- **Spec coverage:** §4.5 catalog-driven dedicated scenarios → Tasks 1–5; auth-consuming scenarios reuse #3's `topology-role.auth` plumbing → Tasks 2,3,4; real configs, unmodified tests → Tasks 2,4.
- **Placeholder scan:** the catalog placeholder tokens (`SCENARIO_SVC`, `CA_BUNDLE`, …) are a documented, deliberately-substituted indirection (schema.md + `scenario-render.sh`), not TODOs. Task 1's test ordering dependency on Task 2 is called out explicitly.
- **Name consistency:** placeholder→resolved mapping in `scenario-render.sh` matches #1's Secret/ConfigMap contract (`<rel>-ca-bundle`, `<rel>-pki`, `<rel>-grid-ca`, `<rel>-token-issuer`, `<rel>-vomsdir`) and #3's `topology-role.auth` field names (`caBundle`, `hostCertSecret`, `crlUrl`, `jwksUrl`); `configKey`→`configs/<key>.conf` matches #2/#3.
