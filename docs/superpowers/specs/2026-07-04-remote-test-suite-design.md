# Remote Test Suite — Design

**Date:** 2026-07-04
**Status:** Approved design (pre-implementation)
**Builds on:** the Kubernetes test lab (`docs/superpowers/specs/2026-07-04-k8s-test-lab-design.md`)

---

## 1. Purpose & Goal

Run **as many of the project's ~390 pytest files as possible from a separate client
container against a remote brix/XRootD instance** deployed in the k8s lab. Keep the
original `tests/` tree untouched; work against an **editable copy** inside the k8s
infrastructure, adapting individual tests so they execute remotely (per-test edits are
explicitly in scope). Where a test must inspect a service's server-side files, it may
read them from the service on demand — but pure over-the-wire execution is preferred.

### Success criteria

1. A `brix-client` container runs the copied suite in the conftest's REMOTE mode
   (`TEST_SERVER_HOST` set) against a remote server, with **working pyxrootd bindings**.
2. The **~267 pure-remote files** (no server-side file access) pass with no per-test edits.
3. The **~123 server-file-inspection files** are adapted (batched by family) to read
   server files via a `svc_read()` helper (`kubectl exec`), passing remotely; only
   fundamentally-local checks `pytest.skip`.
4. `xrd-lab test remote-suite [selection]` drives it end-to-end and reports pass/fail/skip
   + JUnit.
5. The original `tests/` tree is never modified.

### Non-goals

- Changing the original suite or its local workflow.
- Running the genuinely multi-node-topology tests here (cms/hybrid/upstream/cache-tier —
  those are the k8s-lab #5 territory; a few may follow later).
- 100% pass rate — some checks are fundamentally local and will skip with a reason.

---

## 2. Key technical findings (verified)

- **The "dead XrdCl" was a missing package.** `tests/_xrdcl_proxy.py` starts a subprocess
  (`_xrdcl_worker.py`) that does `from XRootD import client` — the real **pyxrootd**
  bindings. The lab's runner image installed `xrootd-client` (CLI) but not the bindings, so
  the worker died and every proxy-based test errored. **`python3-xrootd` (pyxrootd 5.9.6) is
  in EPEL** for almalinux:9 — installing it revives the worker. ~39 files use the proxy
  directly; many more via helpers.
- **conftest REMOTE mode already exists** (`TEST_SERVER_HOST` → no local fleet start,
  connect to that host; `requires_local_server` auto-skip; 378/390 files remote-capable).
- **Single-host model:** REMOTE mode reaches every tier as `SERVER_HOST:<port>`. So the
  remote target must be ONE server exposing every port the suite uses (the local fleet
  behaves the same — everything on localhost).
- **Coverage split:** ~267/390 files are pure over-the-wire; ~123 touch server-side paths
  (`DATA_DIR`, cache dirs, `os.listdir`, `.cinfo`). Some of the 123 only need a client-local
  scratch dir to *exist*; others genuinely inspect what the server wrote.
- **Client-PKI** layout already solved by `k8s-tests/tools/client-pki-init.sh`.

---

## 3. Architecture

### 3.1 Sub-project A — Foundation (unlocks the ~267 pure-remote files)

**A1. Editable suite copy — `k8s-tests/remote-suite/`**
A verbatim, one-time fork of everything the suite needs: `tests/` (all `test_*.py`,
`conftest.py`, `settings.py`, `_*_helpers.py`, `configs/`, `utils/…` refs), the `XRootD/`
shadow package, `_xrdcl_proxy.py`/`_xrdcl_worker.py`, and `utils/`. Originals are never
touched. A `tools/sync-remote-suite.sh` refreshes un-adapted files from the originals;
adapted files carry a marker header (`# brix-remote-adapted`) so sync skips them.

**A2. Client image — `brix-client`**
almalinux:9 + EPEL + **`python3-xrootd`** (pyxrootd — the unlock) + `xrootd-client` +
`python3.12` + pytest/requests/cryptography/pyjwt + `kubectl` + the copied suite +
`client-pki-init.sh`. Entrypoint (`client-entry.sh`): `mkdir -p $TEST_ROOT/data`, run
`client-pki-init.sh` when auth material is mounted, then `exec "$@"` (default a shell).

**A3. Mega server — `topology-role` config `fleet-mega.conf`**
One nginx-xrootd pod exposing **every port the single-node suite uses**, from concatenated
server blocks (`nginx_shared.conf`'s anon/gsi/tls/token/webdav/s3/metrics + the single-node
dedicated configs: readonly, crl, vo_acl, tpc-ssrf, s3-presigned, security-levels, …),
consuming the authority plane (CA/host-cert mounted, JWKS fetched). Fronted by one Service
`<rel>-mega` with all those ports, so a single `TEST_SERVER_HOST=<rel>-mega` reaches
everything. Built mechanically from the existing config fragments (dedupe shared listens).

**A4. Server-file access — `svc_read()` helper (`remote-suite/klib.py`)**
`svc_read(service, path)` → `kubectl exec` into the service pod and cat the file (returns
bytes/str); `svc_listdir(service, path)`, `svc_exists(service, path)` alongside. The client
pod runs under a ServiceAccount with a read-only Role (`pods/exec`, `pods` get/list in the
suite namespace). Used only by adapted tests (Sub-project B). Honors `KUBECTL` / namespace
env.

**A5. Runner + report**
`xrd-lab test remote-suite [selection]`: deploy authorities + mega server, run the copied
suite (in REMOTE mode, pyxrootd live) as a Job or client pod with `TEST_SERVER_HOST=<rel>-mega`
+ client-PKI mounted, collect pass/fail/skip + JUnit. A `tools/remote-coverage.sh` classifies
every copied file as pure-remote / adapted / server-local-skip so progress is visible.

### 3.2 Sub-project B — Per-test adaptation (iterative batches)

Walk the ~123 server-file-inspection files in the copy, batched by family
(cache/cinfo → file-api → write-through → s3 → webdav → checksum → …). For each: replace
server-side local reads with `svc_read()/svc_listdir()` against the mega server's pod, or
`pytest.skip("server-local check")` where the assertion is fundamentally local. Mark each
adapted file with the `# brix-remote-adapted` header. Each batch is verified by running that
family remotely (green or clean-skip) before moving on. Coverage report tracks the burn-down.

### 3.3 Data flow

```
brix-client pod (copied suite + pyxrootd)
   │  root:// / davs:// / S3 over the wire (TEST_SERVER_HOST=<rel>-mega:<port>)
   ▼
<rel>-mega  (one nginx-xrootd pod, all ports)  ── consumes ──▶ auth-authority plane
   ▲
   │  kubectl exec (svc_read) for adapted file-inspection tests
brix-client (ServiceAccount + read RBAC)
```

---

## 4. Sub-project boundaries

| # | Sub-project | Delivers | Done when |
|---|---|---|---|
| **A** | Foundation | copied suite tree, `brix-client` image (pyxrootd), `fleet-mega.conf` + mega Service, `svc_read` helper + RBAC, `xrd-lab test remote-suite`, coverage report | the ~267 pure-remote files run remotely (pass/clean-skip) against the mega server, pyxrootd worker alive |
| **B** | Adaptation | the ~123 file-inspection files adapted (by family) to `svc_read` or documented skip | each family runs remotely green/clean-skip; coverage report shows the burn-down |

A is one implementation plan. B is a batched program (one plan or a rolling checklist).

---

## 5. Risks & mitigations

| Risk | Mitigation |
|---|---|
| pyxrootd version vs server protocol mismatch | pin `python3-xrootd` 5.x from EPEL; the server speaks stock XRootD wire; verify with a handshake smoke first |
| Mega config port/directive conflicts | server blocks are independent per-port; dedupe shared listens; `nginx -t` gate in the image entrypoint catches conflicts |
| `kubectl exec` RBAC/perf for svc_read | narrow read-only Role (pods, pods/exec in-namespace); svc_read used only by the ~123, cached per-call |
| Copy drift from originals | one-time fork + `sync-remote-suite.sh` that skips `# brix-remote-adapted` files; coverage report flags divergence |
| Some tests assume xdist / local fleet lifecycle | run `-p no:xdist`; REMOTE mode already disables fleet lifecycle; `requires_local_server` auto-skip |
| This sandbox saturation / multi-node | foundation runs against a single mega pod on one node; capable-host note in docs |

---

## 6. What this reuses from the k8s lab

`topology-role` (mega role), `auth-authority` (CA/JWKS), `client-pki-init.sh`, `test-runner`
patterns (tiers/JUnit/results), `xrd-lab` driver + scenario dispatch, the profile/values
conventions. The mega server is a new `configKey`; the client is a new image; the copied
suite + `svc_read` + coverage/sync tools are new under `k8s-tests/remote-suite/` and
`k8s-tests/tools/`.
