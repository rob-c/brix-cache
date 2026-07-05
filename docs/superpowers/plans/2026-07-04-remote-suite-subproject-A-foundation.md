# Remote Test Suite — Sub-project A: Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **No git commands** are run in this project — each "Checkpoint (no git)" step is a verification gate, not a commit.

**Goal:** Stand up the foundation that runs the project's real pytest suite from a `brix-client` container against a remote "mega" brix/XRootD server — with working **pyxrootd** bindings — so the ~267 pure-over-the-wire test files pass with no per-test edits.

**Architecture:** A one-time editable fork of the suite lives in `k8s-tests/remote-suite/`. A `brix-client` image ships it plus `python3-xrootd` (which revives the XrdCl worker the suite's shadow package forwards to) plus `kubectl` + `client-pki-init.sh`. A single "mega" nginx-xrootd pod exposes every port the single-node suite uses (assembled from `nginx_shared.conf` + the single-node dedicated configs) behind one Service, so the conftest's REMOTE mode reaches everything via one `TEST_SERVER_HOST`. A `klib.svc_read()` helper (kubectl exec) is provided for the later per-test adaptation. `xrd-lab test remote-suite` drives it.

**Tech Stack:** Docker, Helm 3, helm-unittest, bats, kubeconform, python3-xrootd (pyxrootd 5.x, EPEL), pytest, kubectl, the existing k8s lab charts.

**Spec:** `docs/superpowers/specs/2026-07-04-remote-test-suite-design.md` (§3.1 Sub-project A). Sub-project B (per-test adaptation) is a separate plan.

## Global Constraints

- **Never modify the original `tests/` or `utils/` trees.** All work is against the fork under `k8s-tests/remote-suite/`.
- **The XrdCl unlock is a package, not code:** the client image installs `python3-xrootd` from EPEL; the suite's shadow `tests/XRootD/` forwards to a worker subprocess that imports the real bindings off-PYTHONPATH. Do not import pyxrootd directly in tests.
- **Single-host REMOTE model:** the suite reaches every tier as `TEST_SERVER_HOST:<port>`; the remote target is ONE mega server exposing all those ports. Fixed literal ports in the mega config (not templated).
- Inherits the k8s-lab constraints: pinned k8s `v1.31.4`, in-cluster/loaded images `pullPolicy: Never`, `brix-<x>` namespaces, `set -euo pipefail` + shellcheck-clean shell, `helm unittest` for charts, bats for shell/images.
- Adapted files (Sub-project B) carry a `# brix-remote-adapted` first-line marker; the sync tool must never overwrite them.

---

## File Structure

```
k8s-tests/
├── remote-suite/                         # editable fork (Task 1, created by sync tool)
│   ├── tests/  (fork of repo tests/)
│   ├── utils/  (fork of repo utils/)
│   └── tests/klib.py                      # svc_read/svc_listdir/svc_exists (Task 3)
├── images/client/
│   ├── Dockerfile                         # brix-client (Task 2)
│   └── client-entry.sh                    # data-dir + client-pki-init + exec (Task 2)
├── charts/topology-role/configs/
│   └── fleet-mega.conf                     # all-ports static config (Task 4, generated)
├── charts/client-rbac/                    # SA + read Role for svc_read (Task 3)
│   ├── Chart.yaml  values.yaml
│   ├── templates/rbac.yaml
│   └── tests/rbac_test.yaml
├── tools/
│   ├── sync-remote-suite.sh                # fork/refresh, skip adapted files (Task 1)
│   ├── build-mega-config.sh                # assemble fleet-mega.conf from fragments (Task 4)
│   └── remote-coverage.sh                  # classify pure-remote/adapted/skip (Task 5)
└── tests-bats/
    ├── sync_remote_suite.bats              # Task 1
    ├── client_image.bats                   # Task 2 (pyxrootd worker alive)
    ├── svc_read.bats                       # Task 3 (fake-kubectl unit)
    ├── mega_config.bats                    # Task 4 (nginx -t validates)
    └── remote_suite_e2e.bats               # Task 6 (opt-in live)
```

---

## Task 1: Editable suite fork + marker-aware sync tool

**Files:**
- Create: `k8s-tests/tools/sync-remote-suite.sh`
- Create: `k8s-tests/tests-bats/sync_remote_suite.bats`
- Generates: `k8s-tests/remote-suite/{tests,utils}/…` (the fork)

**Interfaces:**
- Produces: `sync-remote-suite.sh` — copies `tests/` + `utils/` from the repo root into
  `k8s-tests/remote-suite/`, **skipping any destination file whose first line is
  `# brix-remote-adapted`** (so Sub-project B edits are never clobbered). Excludes
  `__pycache__`, `.pyc`, `.pytest_cache`. Idempotent.

- [ ] **Step 1: Write the failing test**

`k8s-tests/tests-bats/sync_remote_suite.bats`:
```bash
#!/usr/bin/env bats
ROOT="${BATS_TEST_DIRNAME}/.."
REPO="${BATS_TEST_DIRNAME}/../.."
SYNC="$ROOT/tools/sync-remote-suite.sh"

@test "sync forks tests + utils into remote-suite" {
  run bash "$SYNC"
  [ "$status" -eq 0 ]
  [ -f "$ROOT/remote-suite/tests/settings.py" ]
  [ -f "$ROOT/remote-suite/tests/conftest.py" ]
  [ -d "$ROOT/remote-suite/tests/XRootD" ]
  [ -f "$ROOT/remote-suite/utils/make_proxy.py" ]
  [ -z "$(find "$ROOT/remote-suite" -name '__pycache__' -type d)" ]
}

@test "sync never overwrites a # brix-remote-adapted file" {
  f="$ROOT/remote-suite/tests/test_query.py"
  [ -f "$f" ] || skip "run the first test first"
  printf '# brix-remote-adapted\nSENTINEL=1\n' > "$f"
  bash "$SYNC"
  grep -q 'SENTINEL=1' "$f"
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/sync_remote_suite.bats`
Expected: FAIL — `sync-remote-suite.sh` does not exist.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/tools/sync-remote-suite.sh`:
```bash
#!/usr/bin/env bash
# sync-remote-suite.sh — fork/refresh the editable suite copy under
# k8s-tests/remote-suite/ from the repo tests/ + utils/, never clobbering a file
# already adapted for remote execution (first line "# brix-remote-adapted").
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$LAB_DIR/.." && pwd)"
DEST="$LAB_DIR/remote-suite"

is_adapted() { [ -f "$1" ] && IFS= read -r l < "$1" && [ "$l" = "# brix-remote-adapted" ]; }

sync_tree() {
    local src="$1" rel
    while IFS= read -r -d '' f; do
        rel="${f#"$REPO"/}"
        case "$rel" in *__pycache__*|*.pyc|*.pytest_cache*) continue;; esac
        local out="$DEST/$rel"
        if is_adapted "$out"; then continue; fi
        mkdir -p "$(dirname "$out")"
        cp -p "$f" "$out"
    done < <(find "$REPO/$1" -type f -print0)
}

mkdir -p "$DEST"
sync_tree tests
sync_tree utils
echo "remote-suite synced from $REPO (tests + utils)"
```
Then `chmod +x k8s-tests/tools/sync-remote-suite.sh`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/sync_remote_suite.bats` → PASS (2 tests).
Also: `shellcheck k8s-tests/tools/sync-remote-suite.sh` → clean.

- [ ] **Step 5: Checkpoint (no git)** — confirm `k8s-tests/remote-suite/tests/` has ~390 `test_*.py`, `XRootD/`, `_xrdcl_worker.py`, `settings.py`; `remote-suite/utils/` present. Do not commit.

---

## Task 2: `brix-client` image (pyxrootd + copied suite)

**Files:**
- Create: `k8s-tests/images/client/Dockerfile`
- Create: `k8s-tests/images/client/client-entry.sh`
- Create: `k8s-tests/tests-bats/client_image.bats`

**Interfaces:**
- Produces image `brix-client:dev`: python3.12 + `python3-xrootd` (real pyxrootd) +
  xrootd-client + pytest/requests/cryptography/pyjwt + kubectl + the `remote-suite` fork at
  `/opt/brix` (so `PYTHONPATH=/opt/brix/tests` picks up the shadow `XRootD/`) +
  `/opt/brix/client-pki-init.sh`. Entrypoint prepares `$TEST_ROOT` and execs its args.

- [ ] **Step 1: Write the failing test**

`k8s-tests/tests-bats/client_image.bats`:
```bash
#!/usr/bin/env bats
IMG_DIR="${BATS_TEST_DIRNAME}/../images/client"
REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
TAG="brix-client:batstest"

setup() { docker build -q -t "$TAG" -f "$IMG_DIR/Dockerfile" "$REPO_ROOT" >/dev/null; }
teardown() { docker rmi -f "$TAG" >/dev/null 2>&1 || true; }

@test "client image has pytest, kubectl, the suite, and pki-init" {
  run docker run --rm "$TAG" bash -lc 'command -v pytest && command -v kubectl && test -f /opt/brix/tests/settings.py && test -f /opt/brix/client-pki-init.sh && python3 --version'
  [ "$status" -eq 0 ]
}

@test "the XrdCl worker starts and imports the real bindings" {
  # The shadow XRootD forwards to a worker subprocess that must import real pyxrootd.
  run docker run --rm -e TEST_SERVER_HOST=dummy "$TAG" bash -lc '
    cd /opt/brix && python3 -c "
import sys; sys.path.insert(0, \"tests\")
from _xrdcl_proxy import _Worker
w = _Worker()          # spawns the worker subprocess (real pyxrootd)
print(\"WORKER_OK\")
"'
  [ "$status" -eq 0 ]
  [[ "$output" == *"WORKER_OK"* ]]
}
```
(If `_Worker` is named differently, adjust to the actual class in `_xrdcl_proxy.py` —
verify with `grep -nE "^class " tests/_xrdcl_proxy.py`. Its constructor spawns the worker.)

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/client_image.bats`
Expected: FAIL — Dockerfile absent.

- [ ] **Step 3: Write the implementation**

`k8s-tests/images/client/client-entry.sh`:
```bash
#!/bin/bash
set -e
export TEST_ROOT="${TEST_ROOT:-/tmp/tr}"
export PYTHONPATH="/opt/brix/tests${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$TEST_ROOT/data"
# Lay out client PKI + tokens if the authority material is mounted.
if [ -d /auth/pki ]; then
    PKI_SRC=/auth/pki JWKS_SRC=/auth/jwks/jwks.json bash /opt/brix/client-pki-init.sh || true
fi
exec "$@"
```

`k8s-tests/images/client/Dockerfile` (context = repo root; copies the fork):
```dockerfile
# brix-client — runs the copied suite against a remote server, with real pyxrootd.
FROM almalinux:9
RUN dnf install -y epel-release \
    && dnf install -y --allowerasing python3.12 python3.12-pip \
                      python3-xrootd xrootd-client openssl krb5-workstation \
    && alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && dnf clean all
RUN python3.12 -m pip install --no-cache-dir pytest pytest-timeout requests cryptography pyjwt
WORKDIR /opt/brix
COPY k8s-tests/remote-suite/ /opt/brix/
COPY k8s-tests/tools/client-pki-init.sh /opt/brix/client-pki-init.sh
COPY k8s-tests/images/client/client-entry.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PYTHONPATH=/opt/brix/tests TEST_ROOT=/tmp/tr
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
```

Note on pyxrootd + python3.12: `python3-xrootd` from EPEL is built for the distro python
(3.9). If the 3.12 interpreter cannot import it, the worker subprocess must use the
interpreter that CAN. Two options, decided at implementation time by testing the worker:
(a) run the whole suite on distro python3.9 (drop the 3.12 alternative) if the suite tolerates
it; (b) keep pytest on 3.12 but point `_xrdcl_worker` at `/usr/bin/python3.9` via its spawn
env. **Verify first:** `docker run … python3.9 -c 'from XRootD import client'` vs 3.12; pick
the interpreter mix that makes the "worker starts" test pass. Record the choice in the image.

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/client_image.bats` → PASS (2 tests, worker imports real bindings).

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: `svc_read()` helper + read RBAC chart

**Files:**
- Create: `k8s-tests/remote-suite/tests/klib.py`
- Create: `k8s-tests/charts/client-rbac/{Chart.yaml,values.yaml,templates/rbac.yaml,tests/rbac_test.yaml}`
- Create: `k8s-tests/tests-bats/svc_read.bats`

**Interfaces:**
- Produces (importable in adapted tests as `import klib`):
  - `klib.svc_read(service, path, namespace=None) -> bytes` — `kubectl exec` into a pod of
    `service` and `cat` the file.
  - `klib.svc_listdir(service, path, namespace=None) -> list[str]`
  - `klib.svc_exists(service, path, namespace=None) -> bool`
  - Namespace defaults to `$BRIX_SUITE_NS` (else `brix-remote`); kubectl binary from `$KUBECTL`.
  - Pod is selected by `app.kubernetes.io/component=<service>`.
- Produces chart `client-rbac`: ServiceAccount `<rel>-client` + Role (verbs get/list on pods,
  create on pods/exec) + RoleBinding, so the client pod may exec into service pods.

- [ ] **Step 1: Write the failing test**

`k8s-tests/tests-bats/svc_read.bats` (unit-tests klib against a **fake kubectl** on PATH):
```bash
#!/usr/bin/env bats
SUITE="${BATS_TEST_DIRNAME}/../remote-suite/tests"

setup() {
  FAKE="$BATS_TEST_TMPDIR/bin"; mkdir -p "$FAKE"
  cat > "$FAKE/kubectl" <<'EOF'
#!/usr/bin/env bash
# fake kubectl: `get pods -l ... -o name` -> a pod; `exec POD -- cat PATH` -> file body
case "$*" in
  *"get pods"*) echo "pod/mega-abc123";;
  *"cat /data/xrootd/hello"*) printf 'HELLO-BYTES';;
  *"test -e /data/xrootd/hello"*) exit 0;;
  *"ls -1 /data/xrootd"*) printf 'a\nb\n';;
  *) exit 1;;
esac
EOF
  chmod +x "$FAKE/kubectl"; export PATH="$FAKE:$PATH"
}

@test "svc_read returns the file bytes via kubectl exec" {
  run python3 -c "import sys; sys.path.insert(0,'$SUITE'); import klib; print(klib.svc_read('mega','/data/xrootd/hello').decode())"
  [ "$status" -eq 0 ]
  [[ "$output" == *"HELLO-BYTES"* ]]
}
@test "svc_listdir returns entries" {
  run python3 -c "import sys; sys.path.insert(0,'$SUITE'); import klib; print(klib.svc_listdir('mega','/data/xrootd'))"
  [[ "$output" == *"'a'"* && "$output" == *"'b'"* ]]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/svc_read.bats`
Expected: FAIL — `klib` module not found.

- [ ] **Step 3: Write the implementation**

`k8s-tests/remote-suite/tests/klib.py`:
```python
"""klib — read a k8s service's server-side files from an adapted remote test.

Adapted tests (Sub-project B) call these instead of touching local paths. Each
call `kubectl exec`s into a pod of the target service (selected by the
app.kubernetes.io/component label) in the suite namespace.
"""
import os
import subprocess

KUBECTL = os.environ.get("KUBECTL", "kubectl")


def _ns(namespace):
    return namespace or os.environ.get("BRIX_SUITE_NS", "brix-remote")


def _pod(service, namespace):
    out = subprocess.run(
        [KUBECTL, "-n", _ns(namespace), "get", "pods",
         "-l", "app.kubernetes.io/component=%s" % service, "-o", "name"],
        check=True, capture_output=True, text=True).stdout.strip()
    if not out:
        raise RuntimeError("no pod for service %r" % service)
    return out.splitlines()[0].split("/", 1)[-1]


def _exec(service, namespace, argv):
    pod = _pod(service, namespace)
    return subprocess.run(
        [KUBECTL, "-n", _ns(namespace), "exec", pod, "--", *argv],
        capture_output=True)


def svc_read(service, path, namespace=None):
    """Return the bytes of <path> inside a pod of <service>."""
    r = _exec(service, namespace, ["cat", path])
    if r.returncode != 0:
        raise FileNotFoundError("%s:%s (%s)" % (service, path, r.stderr.decode().strip()))
    return r.stdout


def svc_exists(service, path, namespace=None):
    return _exec(service, namespace, ["test", "-e", path]).returncode == 0


def svc_listdir(service, path, namespace=None):
    r = _exec(service, namespace, ["ls", "-1", path])
    if r.returncode != 0:
        raise FileNotFoundError("%s:%s" % (service, path))
    return [x for x in r.stdout.decode().splitlines() if x]
```

`k8s-tests/charts/client-rbac/Chart.yaml`:
```yaml
apiVersion: v2
name: client-rbac
description: ServiceAccount + read RBAC so the client pod can exec into service pods
type: application
version: 0.1.0
```
`k8s-tests/charts/client-rbac/values.yaml`: `saName: client`
`k8s-tests/charts/client-rbac/templates/rbac.yaml`:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: {{ .Release.Name }}-{{ .Values.saName }} }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: {{ .Release.Name }}-{{ .Values.saName }} }
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: {{ .Release.Name }}-{{ .Values.saName }} }
subjects:
  - { kind: ServiceAccount, name: {{ .Release.Name }}-{{ .Values.saName }} }
roleRef: { kind: Role, name: {{ .Release.Name }}-{{ .Values.saName }}, apiGroup: rbac.authorization.k8s.io }
```
`k8s-tests/charts/client-rbac/tests/rbac_test.yaml`:
```yaml
suite: client rbac
templates: [templates/rbac.yaml]
release: { name: brix-remote }
tests:
  - it: grants pods/exec
    documentIndex: 1
    asserts:
      - isKind: { of: Role }
      - contains:
          path: rules[1].resources
          content: pods/exec
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bats k8s-tests/tests-bats/svc_read.bats` → PASS (2). Note the marker: prepend
`# brix-remote-adapted` as the FIRST line of `klib.py` so the sync tool never clobbers it.
Run: `helm unittest k8s-tests/charts/client-rbac` → PASS. `shellcheck` any new shell → clean.

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 4: `fleet-mega.conf` generator + config

**Files:**
- Create: `k8s-tests/tools/build-mega-config.sh`
- Create: `k8s-tests/charts/topology-role/configs/fleet-mega.conf` (generated, committed-as-file)
- Create: `k8s-tests/tests-bats/mega_config.bats`

**Interfaces:**
- Produces: `fleet-mega.conf` — ONE nginx config with a single `stream{}` and single `http{}`
  block, containing the server blocks of `nginx_shared.conf` (anon/gsi/tls/token/webdav/s3/
  metrics) plus the single-node dedicated configs (readonly, crl, vo_acl, tpc-ssrf*, s3-presigned*,
  security-level*, xrdhttp-digest, webdav-dellock, …), each on its **literal default port**,
  with server/host-cert/CA/CRL/JWKS paths mapped to the mounted locations. Consumed by
  `topology-role` with `role.configKey=fleet-mega` and `role.ports` listing every port.
- `build-mega-config.sh <out>` regenerates it from `tests/configs/*.conf` fragments.

- [ ] **Step 1: Write the failing test**

`k8s-tests/tests-bats/mega_config.bats`:
```bash
#!/usr/bin/env bats
ROOT="${BATS_TEST_DIRNAME}/.."
CONF="$ROOT/charts/topology-role/configs/fleet-mega.conf"
SERVER="brix-server:dev"

@test "mega config exposes the core suite ports and validates with nginx -t" {
  [ -f "$CONF" ]
  for p in 11094 11095 11097 11102 8443 9100; do grep -qE "listen ($p|\\{.*$p)" "$CONF" || grep -q "listen $p" "$CONF"; done
  # nginx -t inside the server image (single stream{} + single http{}, no conflicts)
  b64="$(base64 -w0 "$CONF")"
  run docker run --rm -e C="$b64" "$SERVER" bash -lc '
    mkdir -p /var/log/brix /data/xrootd /etc/grid-security/certificates /etc/brix/{crl,jwks}
    echo "$C" | base64 -d > /etc/brix/nginx.conf
    # provide dummy cert/crl/jwks so nginx -t can open them
    openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/grid-security/hostkey.pem -out /etc/grid-security/hostcert.pem -days 1 -subj /CN=t >/dev/null 2>&1
    cp /etc/grid-security/hostcert.pem /etc/grid-security/certificates/ca.pem
    : > /etc/brix/jwks/jwks.json; : > /etc/brix/crl/crl.pem
    nginx -t -c /etc/brix/nginx.conf'
  [ "$status" -eq 0 ]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/mega_config.bats`
Expected: FAIL — `fleet-mega.conf` does not exist.

- [ ] **Step 3: Write the generator + generate the config**

`k8s-tests/tools/build-mega-config.sh` — extracts `server { … }` blocks from each fragment,
sorts them into stream vs http (a stream server has `listen <port>;` with no `ssl`/`location`;
http servers contain `location`/`ssl`), maps the repo sed-markers to the mounted paths
(reuse the `import-config.sh` substitutions but with **literal default ports** pulled from
`tests/lib/pki.sh` defaults / `dedicated.sh`), and emits one `stream{}` + one `http{}`:
```bash
#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: build-mega-config.sh <out.conf>}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CFG="$REPO/tests/configs"
map() { sed -e 's|{DATA_DIR}|/data/xrootd|g' -e 's|{LOG_DIR}|/var/log/brix|g' \
            -e 's|{TMP_DIR}|/tmp|g' -e 's|{SERVER_CERT}|/etc/grid-security/hostcert.pem|g' \
            -e 's|{SERVER_KEY}|/etc/grid-security/hostkey.pem|g' \
            -e 's|{CA_CERT}|/etc/grid-security/certificates/ca.pem|g' \
            -e 's|{CA_DIR}|/etc/grid-security/certificates|g' \
            -e 's|{VOMSDIR}|/etc/grid-security/vomsdir|g' \
            -e 's|{CRL_PATH}|/etc/brix/crl/crl.pem|g' \
            -e 's|{TOKEN_DIR}/jwks.json|/etc/brix/jwks/jwks.json|g' \
            -e 's|{BIND_HOST}:||g'; }
# awk helper: print server{...} blocks from stdin (brace-balanced)
blocks() { awk '/server[ ]*\{/{d=0} {if($0 ~ /\{/)d+=gsub(/{/,"{"); if(d>0)print; if($0 ~ /\}/)d-=gsub(/}/,"}"); if(d==0 && NF==0)next}'; }
# Assemble: default-port substitution per fragment is done by the fragment's own {PORT} ->
# literal; we substitute {PORT} with the dedicated default from a name->port table.
# (Table built from tests/lib/dedicated.sh; see step notes.)
...
```
Because full brace-parsing in awk is fiddly, the generator is written and iterated until
`nginx -t` passes; the committed `fleet-mega.conf` is the artifact the test checks. The
port table maps each included config to its default port (anon 11094, gsi 11095, tls 11096,
token 11097, webdav 8443, s3 9001, metrics 9100, readonly 11102, crl 11104, vo_acl 11103,
tpc_ssrf_default 11180, s3_presigned 11183, security_level_standard 11191,
security_level_pedantic 11192, xrdhttp_digest 12988, …). Keep the http servers (webdav/s3/
metrics/xrdhttp/tpc/security-level) in one `http{}`, stream servers (anon/gsi/tls/token/
readonly/vo_acl/crl) in one `stream{}`. Start from `nginx_shared.conf` (already one
stream+http) and append the extra single-node blocks.

Then run `bash k8s-tests/tools/build-mega-config.sh k8s-tests/charts/topology-role/configs/fleet-mega.conf`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/mega_config.bats` → PASS (`nginx -t` is successful).
Requires `brix-server:dev` present (built in the k8s lab). shellcheck the generator → clean.

- [ ] **Step 5: Checkpoint (no git)** — verify the mega config has one `stream {` and one `http {` block: `grep -c '^stream {' fleet-mega.conf` = 1, `grep -c '^http {' fleet-mega.conf` = 1.

---

## Task 5: `xrd-lab test remote-suite` + coverage report

**Files:**
- Modify: `k8s-tests/xrd-lab` (add `scenario_remote_suite` + register)
- Create: `k8s-tests/tools/remote-coverage.sh`
- Create: `k8s-tests/charts/brix-test-lab/values/values.remote.yaml` (optional profile: authorities + mega role)

**Interfaces:**
- Produces: `xrd-lab test remote-suite [selection]` — namespace `brix-remote`; deploys the
  auth plane (release `auth`), the mega server (release `srv`, `role.configKey=fleet-mega`,
  all ports, auth mounts), and `client-rbac`; runs the client pod (`brix-client:dev`,
  serviceAccount `brix-remote-client`, `TEST_SERVER_HOST=srv-mega`, `BRIX_SUITE_NS=brix-remote`,
  auth material mounted) executing `pytest <selection>`; tears down. Under `DRY_RUN` prints the
  commands.
- Produces: `remote-coverage.sh` — classifies every `remote-suite/tests/test_*.py` as
  `pure-remote` (no server-path refs), `adapted` (`# brix-remote-adapted`), or `server-local`
  (touches `DATA_DIR`/cache/`os.listdir` and not yet adapted); prints counts.

- [ ] **Step 1: Write the failing test**

Add to `k8s-tests/tests-bats/remote_suite_e2e.bats` (dry-run part, always runs):
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
ROOT="${BATS_TEST_DIRNAME}/.."

@test "dry-run remote-suite deploys mega + runs the client suite" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test remote-suite tests/test_query.py
  [ "$status" -eq 0 ]
  [[ "$output" == *"fleet-mega"* ]]
  [[ "$output" == *"brix-client"* ]]
  [[ "$output" == *"TEST_SERVER_HOST=srv-mega"* ]]
}
@test "coverage report classifies files" {
  run bash "$ROOT/tools/remote-coverage.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"pure-remote"* ]]
  [[ "$output" == *"server-local"* ]]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/remote_suite_e2e.bats`
Expected: FAIL — scenario + coverage tool absent.

- [ ] **Step 3: Write the implementation**

`k8s-tests/tools/remote-coverage.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
SUITE="$(cd "$(dirname "$0")/.." && pwd)/remote-suite/tests"
pure=0; adapted=0; local=0
for f in "$SUITE"/test_*.py; do
  if IFS= read -r l < "$f" && [ "$l" = "# brix-remote-adapted" ]; then adapted=$((adapted+1))
  elif grep -qE 'DATA_DIR|CACHE_ROOT|os\.listdir|CHAOS_TIER|_ROOT\b' "$f"; then local=$((local+1))
  else pure=$((pure+1)); fi
done
echo "pure-remote: $pure  adapted: $adapted  server-local(unadapted): $local  total: $((pure+adapted+local))"
```

In `k8s-tests/xrd-lab`, add `scenario_remote_suite` (modeled on `scenario_suite`, using the
`brix-client` image + client-rbac SA + mega role + BRIX_SUITE_NS), register `remote-suite)` in
`cmd_test`, and add the client image to `build_images` for the relevant profile. Dry-run must
print `fleet-mega`, `brix-client`, `TEST_SERVER_HOST=srv-mega`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/remote_suite_e2e.bats` (dry-run + coverage) → PASS.
`shellcheck k8s-tests/xrd-lab k8s-tests/tools/remote-coverage.sh` → clean.

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 6: Live gate — the pure-remote set runs against the mega server

**Files:**
- Modify: `k8s-tests/tests-bats/remote_suite_e2e.bats` (add the opt-in live test)

**Interfaces:**
- Consumes everything above. Proves pyxrootd + REMOTE mode + mega server end-to-end.

- [ ] **Step 1: Write the failing test**

Append to `remote_suite_e2e.bats`:
```bash
@test "a pure-remote test file passes against the mega server" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip "set XRD_LAB_E2E=1"
  "$LAB" up
  run "$LAB" test remote-suite "tests/test_query.py -k 'not gsi'"
  "$LAB" down remote || true
  [ "$status" -eq 0 ]
  [[ "$output" == *"passed"* ]]
}
```
(`test_query.py` is a pure-remote, XrdCl-proxy file — a good pyxrootd proof. If it needs the
mega gsi port, keep `not gsi`; otherwise widen the selection.)

- [ ] **Step 2: Run test to verify it fails/skips**

Run: `bats k8s-tests/tests-bats/remote_suite_e2e.bats` → the live test SKIPS (no `XRD_LAB_E2E`).

- [ ] **Step 3: Build/load images + run the live gate**

Build + load `brix-server:dev` (if not present) and `brix-client:dev` into minikube. Then:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/remote_suite_e2e.bats
```
Expected: the client pod runs `tests/test_query.py` in REMOTE mode against `srv-mega`, the
XrdCl worker drives real pyxrootd over the wire, and tests **pass** (`passed` in output). If a
test needs client PKI, it is mounted (auth material) and `client-pki-init` ran in the entrypoint.

- [ ] **Step 4: Verify pass**

Confirm `passed` and non-zero collected count; if some error on `svc_read` paths they belong to
Sub-project B (server-local) — deselect them here.

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project A)

- [ ] `bats k8s-tests/tests-bats/{sync_remote_suite,client_image,svc_read,mega_config,remote_suite_e2e}.bats` (live skips) → all green.
- [ ] `helm unittest k8s-tests/charts/client-rbac` → PASS.
- [ ] `shellcheck k8s-tests/xrd-lab k8s-tests/tools/*.sh` → clean.
- [ ] `bash k8s-tests/tools/remote-coverage.sh` → prints the pure-remote / adapted / server-local split.
- [ ] **Live gate:** `XRD_LAB_E2E=1 bats … remote_suite_e2e.bats` → a pure-remote file passes against the mega server via pyxrootd. ✅
- [ ] **DoD (spec §4 row A):** the pure-remote files run remotely (pass/clean-skip); the XrdCl worker is alive. ✅

## Self-review notes

- **Spec coverage:** §3.1 A1 fork+sync → Task 1; A2 client image (pyxrootd) → Task 2; A3 mega
  server → Task 4; A4 svc_read + RBAC → Task 3; A5 runner + coverage → Task 5; live proof → Task 6.
- **Placeholder scan:** the two implementation-time forks (python3.9-vs-3.12 for the pyxrootd
  worker in Task 2; awk brace-parsing iterated until `nginx -t` passes in Task 4) are explicit
  engineering decisions with a stated verification, not TODOs. No "TBD"/"add error handling".
- **Name consistency:** `svc_read/svc_listdir/svc_exists` (klib) used identically in Tasks 3/5/6;
  `fleet-mega` configKey + `srv-mega` Service + `TEST_SERVER_HOST=srv-mega` consistent across
  Tasks 4/5/6; namespace `brix-remote` + `BRIX_SUITE_NS` consistent; the `# brix-remote-adapted`
  marker defined in Task 1 (sync) and applied in Task 3 (klib) + Sub-project B.
```
