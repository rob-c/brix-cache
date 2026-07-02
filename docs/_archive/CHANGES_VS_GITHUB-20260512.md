# Changes relative to GitHub (origin/main) — 12 May 2026

**Scope:** 21 commits ahead of `origin/main` (rob-c/nginx-xrootd), plus
uncommitted working-tree changes and untracked new files.

Overall: **573 files changed**, +96,254 / −21,886 lines across committed work,
with a further 23 files modified and 8 untracked in the working tree.

---

## 1. Commit summary

| SHA | Subject |
|---|---|
| `a8356c4` | `src/tpc,session/bind:` add XRootD TPC pull and `kXR_bind` (parallel streams); **major source reorganisation** into per-subsystem directories |
| `6c320eb` | `tpc:` decompose `pull.c` into per-concept files for contributor clarity |
| `65ec9b1` | `protocol:` add `kXR_set` handler; define `kXR_attrCache`, `kXR_set` modifier constants |
| `65ac20c` | `pgread:` fix response chain; overhaul test harness; add protocol test suites |
| `92bc13f` | `docs:` add `status.md`; fix background, development, authentication docs |
| `30fc6fa` | `manager/cluster:` add CMS server, dynamic registry, `kXR_clone`, `kXR_chkpoint`, S3 gateway, SSS auth; overhaul docs and tests |
| `48dca85`–`416e2fd` | Ralph iterations 1–1 (work in progress): incremental development across multiple subsystems |
| `549497f`–`50776af` | Ralph iterations 1–1: continued |
| `668b339`–`d7c1f6a` | Ralph iterations 2–3: continued |
| `226f991` | `proxy:` upstream proxy pool (`src/proxy/connect.c`, `pool.c`, `events.c`) |
| `0ec306e` | `k8s-tests:` initial full scaffold — Dockerfiles, Helm charts, k8s manifests, PKI scripts, test runner |
| `2777d0d` | `k8s-tests/PLAN.md:` restructure |
| `2df98ad` | `k8s-tests/PLAN.md` + `src/core/config/process.c` |
| `3ff2ca4` | `k8s-tests:` minikube setup, network policy, resource quota, test-runner improvements |
| `270e307` | `k8s-tests:` GitHub Actions CI, cluster setup/teardown scripts, Keycloak templates, aggregate results script; `docs/deployment-guide.md` |

---

## 2. Source code (`src/`)

### 2.1 Major restructure — monoliths replaced by subsystem directories

The following large monolithic files were deleted and their content distributed
into dedicated subdirectories:

| Deleted file | Moved into |
|---|---|
| `src/ngx_xrootd_connection.c` | `src/connection/` |
| `src/ngx_xrootd_config.c` | `src/core/config/` |
| `src/ngx_xrootd_read_handlers.c` | `src/read/` (20 files) |
| `src/ngx_xrootd_write_handlers.c` | `src/write/` (17 files) |
| `src/ngx_xrootd_query.c` | `src/query/` |
| `src/ngx_xrootd_path.c` | `src/path/` (17 files) |
| `src/ngx_xrootd_gsi.c` | `src/auth/gsi/` |
| `src/ngx_xrootd_token.c` | `src/auth/token/` (16 files) |
| `src/ngx_xrootd_upstream.c` | `src/upstream/` |
| `src/ngx_xrootd_voms.c` | `src/auth/voms/` |
| `src/ngx_xrootd_aio.c` | `src/core/aio/` |
| `src/ngx_xrootd_cms_heartbeat.c` | `src/cms/` |
| `src/ngx_xrootd_handshake.c` | `src/handshake/` (10 files) |
| `src/ngx_xrootd_session.c` | `src/session/` |
| `src/ngx_xrootd_response.c` | `src/response/` |
| `src/ngx_http_xrootd_webdav_*.c` (4 files) | `src/webdav/` (34 files) |
| `src/ngx_http_xrootd_metrics_module.c` | `src/metrics/` |
| `src/xrootd_protocol.h` | `src/protocol/wire.h` + companion headers |
| `src/ngx_xrootd_metrics.h` | `src/metrics/metrics.h` |

`src/core/ngx_xrootd_module.h` kept but substantially reorganised (−715 /+821 lines
net).

### 2.2 New protocol features

- **`kXR_bind` — parallel streams** (`src/session/bind.c`, `src/session/`).
  Bound secondaries are read-only; primary is the control channel.

- **XRootD TPC pull** (`src/tpc/`): full third-party-copy client.  Decomposed
  into: `bootstrap.c`, `connect.c`, `done.c`, `gsi_outbound.c`, `io.c`,
  `launch.c`, `source.c`, `thread.c`, `tpc_token.c`, `parse.c`.

- **`kXR_set`** handler with `kXR_attrCache` and modifier constants
  (`src/query/set.c`, `src/protocol/opcodes.h`).

- **`kXR_clone`** (`src/read/clone.c`) — fast-path TPC for local copies.

- **`kXR_chkpoint`** (`src/write/chkpoint.c`, `src/write/chkpoint_xeq.c`).

- **pgread response framing fix** — `kXR_pgread` now correctly uses `kXR_status`
  (4007) with per-page CRC32c; was incorrectly using the standard chunk framing.

### 2.3 New subsystems

| Directory | Purpose |
|---|---|
| `src/cache/` | Read-through cache (eviction, config, AIO integration) |
| `src/proxy/` | Upstream proxy pool — connection pooling, event handling, forwarding |
| `src/s3/` | S3-compatible REST gateway: GET/PUT/DELETE, ListObjectsV2, multipart upload, SigV4 auth |
| `src/auth/sss/` | SSS (Shared-Secret-Security) authentication |
| `src/manager/` | Dynamic manager/registry state |
| `src/cms/` | CMS heartbeat, space/load reporting, multi-server config |
| `src/fattr/` | Extended attribute operations (`kXR_fattr` get/set/del) |
| `src/dirlist/` | Native directory listing (`kXR_dirlist`) |
| `src/auth/crypto/` | Shared PKI loading and verification helpers |

### 2.4 WebDAV (`src/webdav/`) — new and expanded handlers

New handlers not previously in the monolith:

- `copy.c` — RFC 4918 §9.8 server-side COPY
- `move.c` — MOVE with lock enforcement
- `lock.c` — LOCK / UNLOCK (WebDAV locking)
- `proxy.c` — upstream proxy forwarding mode
- `cors.c` — CORS header insertion
- `tpc_cred.c` — TPC credential delegation (oidc-agent, RFC 8693 token exchange)
- `auth_store.c` — auth credential store / cache
- `fd_cache.c` — per-connection fd cache
- `io.c` — `copy_file_range(2)` + pread/write fallback
- `resource.c`, `date.c`, `headers.c` — helpers

### 2.5 Metrics (`src/metrics/`)

Fully rewritten as a proper multi-file module: `export.c`, `handler.c`,
`module.c`, `writer.c`, `metrics_internal.h`, `stream.c`.  WebDAV metrics
moved to `src/webdav/metrics.c`, S3 metrics to `src/s3/metrics.c`.

### 2.6 Uncommitted working-tree changes to `src/`

| File | Change |
|---|---|
| `src/connection/handler.c` | +18 lines |
| `src/metrics/metrics.h` | +62 lines (new counter definitions) |
| `src/metrics/stream.c` | +13 lines |
| `src/proxy/connect.c` | +11 lines |
| `src/proxy/events.c` | +13 lines |
| `src/proxy/forward.c` | +26 lines (proxy forwarding improvements) |
| `src/proxy/pool.c` | −4 / +4 lines |
| `src/proxy/proxy_internal.h` | −5 / +5 lines |

---

## 3. Tests (`tests/`)

### 3.1 Test harness overhaul

- `conftest.py` — rebuilt (+77 lines net vs origin)
- `settings.py` — new centralised settings module
- `pki_helpers.py` — new PKI fixture helpers (+180 lines)
- `server_control.py` — new server lifecycle helpers
- `manage_test_servers.sh` — updated (+48 lines)
- Test configs extracted to `tests/configs/` (8 config files)

### 3.2 New test files (not in origin/main)

| Test file | Coverage |
|---|---|
| `test_new_opcodes.py` | `kXR_pgread`, `kXR_pgwrite` CRC32c, `kXR_set`, `kXR_clone` |
| `test_pgwrite_checksum.py` | pgwrite CRC32c verify |
| `test_session_bind.py` | `kXR_bind` parallel streams |
| `test_sigver_verify.py` | `kXR_sigver` signing |
| `test_opcode_coverage.py` | Raw-wire opcode coverage |
| `test_opcode_flag_coverage.py` | Open/stat/locate flag combinations |
| `test_io_edge_cases.py` | I/O boundary conditions |
| `test_protocol_edge_cases.py` | Protocol framing edge cases |
| `test_prepare_staging.py` | `kXR_prepare` staging |
| `test_concurrent.py` | Concurrent request handling |
| `test_conformance.py` | nginx-xrootd vs reference xrootd |
| `test_s3.py` | S3 GET/PUT/DELETE/list |
| `test_s3_multipart.py` | S3 multipart upload lifecycle |
| `test_s3_status_codes.py` | S3 HTTP status codes |
| `test_http_webdav.py` | WebDAV over plain HTTP |
| `test_http_webdav_status_codes.py` | HTTP WebDAV status matrix |
| `test_https_webdav_status_codes.py` | HTTPS WebDAV status matrix |
| `test_http_webdav_lock.py` | LOCK / UNLOCK |
| `test_http_webdav_lock_recursive.py` | Recursive LOCK |
| `test_tpc_ssrf_policy.py` | HTTP-TPC SSRF protection |
| `test_tpc_token_mode.py` | HTTP-TPC token mode |
| `test_webdav_tpc_cred.py` | TPC credential delegation |
| `test_webdav_spooled_put.py` | Spooled PUT via nginx body buffer |
| `test_webdav_proxy.py` | WebDAV upstream proxy mode |
| `test_token_macaroon.py` | Macaroon token validation |
| `test_token_security.py` | Token security negative cases |
| `test_gsi_security.py` | GSI security hardening |
| `test_gsi_bridge.py` | GSI bridge mode |
| `test_security_hardening.py` | Path traversal, auth bypass |
| `test_wire_protocol_security.py` | Wire-level security |
| `test_privilege_escalation.py` | Privilege escalation prevention |
| `test_authdb.py` | Auth DB integration |
| `test_query_extended.py` | Extended `kXR_query` subtypes |
| `test_fattr_query.py` | `kXR_fattr` extended attributes |
| `test_proxy_mode.py` | Native upstream proxy mode |
| `test_throughput.py` | Throughput benchmarks |
| `test_metrics.py` | Prometheus metrics endpoint |
| `tests/unit/` | C unit tests for b64url, JSON, PKI check, scopes |

---

## 4. Kubernetes test infrastructure (`k8s-tests/`) — new from scratch

Nothing in this directory existed in origin/main.

### 4.1 Container images (`k8s-tests/Dockerfiles/`)

| Image | Purpose |
|---|---|
| `server/Dockerfile` + `entrypoint.sh` | nginx-xrootd server container |
| `client/Dockerfile` | XRootD client tools container |
| `test-runner/Dockerfile` | pytest test runner container |
| `rpm-builder/Dockerfile` | AlmaLinux 9 RPM build container |

### 4.2 Helm charts

**`server-helm/`** — deploys nginx-xrootd server:
- `templates/deployment.yaml`, `service.yaml`, `configmap.yaml`, `pvc.yaml`, `secret.yaml`
- `values.yaml`, `values.dev.yaml`, `values.prod.yaml`

**`test-infra-helm/`** — test infrastructure:
- CRL server, server certificate, namespace, network policy, resource quota
- Keycloak OIDC integration (templates added then removed in working tree — replaced by JWT-based approach; see §6)

### 4.3 Raw Kubernetes manifests (`k8s-tests/k8s-manifests/`)

- `namespace.yaml`, `deployment-server.yaml`, `service.yaml`
- `configmap-nginx.conf.yaml`, `job-test-run.yaml`
- `network-policy-xrootd.yaml`, `resource-quota.yaml`

### 4.4 PKI scripts (`k8s-tests/pki-scripts/`)

- `generate-ca.sh` — self-signed test CA
- `generate-server-cert.sh` — host certificate signed by test CA
- `generate-proxy-certs.sh` — RFC 3820 proxy certificates
- `manage-crl.sh` — CRL generation and management
- `setup-voms-attributes.sh` — VOMS VO/FQAN attributes

### 4.5 Cluster management scripts (`k8s-tests/scripts/`)

- `setup-minikube.sh` — full minikube cluster bootstrap (+251 lines)
- `setup-cluster.sh` — generic cluster setup
- `teardown-cluster.sh`, `teardown.sh` — cluster teardown

### 4.6 CI (`k8s-tests/.github/workflows/build.yaml`)

GitHub Actions workflow: build RPM → build container images → push to registry →
deploy to test cluster → run test suite → collect results.

### 4.7 Test runner (`k8s-tests/test-runner/`)

- `run_tests.py` — pytest orchestration inside the cluster (+215 lines from commit 3ff2ca4)
- `aggregate_results.py` — multi-node result aggregation (+195 lines)
- `conftest.py`, `values.test.yaml`

---

## 5. Documentation (`docs/`)

### 5.1 New doc files

| File | Content |
|---|---|
| `docs/status.md` | Implementation status matrix for all XRootD opcodes |
| `docs/deployment-guide.md` | Production deployment reference (+207 lines) |
| `docs/architecture/index.md`, `stream.md`, `webdav.md`, `s3.md` | Architecture diagrams and code-path descriptions |
| `docs/comparison/` (4 files) | Comparison with reference xrootd by the numbers, design rationale, deployment guide |
| `docs/configuration/directives.md`, `index.md`, `quick-reference.md`, `examples.md` | Full directive reference |
| `docs/contributing/` (4 files) | Code style, extending, worked examples, index |
| `docs/metrics/` (7 files) | Metrics overview, access logging, setup, PromQL examples, extended metrics |
| `docs/operations/` | Operations reference |
| `docs/optimizations/` | Per-area optimisation notes |
| `docs/pki/` | Grid PKI, GSI auth, proxy certificates |
| `docs/webdav/` | WebDAV method behaviour and RFC compliance |
| `docs/testing/` | Test harness docs, port table, PKI fixtures |

### 5.2 Substantially revised

`docs/authentication.md`, `docs/background.md`, `docs/building.md`,
`docs/development.md`, `docs/feature-roadmap.md`, `docs/getting-started.md`,
`docs/manager-mode.md`, `docs/cluster-mode.md`, `docs/configuration.md`,
`docs/metrics-and-logging.md`, `docs/tpc-comparison.md`.

---

## 6. Packaging (`packaging/rpm/`)

### In committed work

- `nginx-mod-xrootd.spec` — `voms-libs` and `curl` promoted from `Recommends`
  to `Requires`; `openssl-libs` added as explicit `Requires`.  Both are
  invisible to `find-requires` (dlopen / fork-exec) so must be declared manually.

- `packaging/rpm/README.md` — updated with WLCG repo install steps per EL
  version and rationale table.

### Uncommitted changes (working tree)

- `packaging/rpm/nginx-mod-xrootd.spec` — minor further tweaks (−6 / +6 lines)
- `packaging/rpm/README.md` — significant extension (+92 lines) covering
  container-based multi-distro build workflow

### Untracked new files

| File | Purpose |
|---|---|
| `packaging/rpm/Dockerfile.alma8` | Container RPM builder for AlmaLinux 8 |
| `packaging/rpm/Dockerfile.alma9` | Container RPM builder for AlmaLinux 9 |
| `packaging/rpm/Dockerfile.alma10` | Container RPM builder for AlmaLinux 10 |
| `packaging/rpm/Dockerfile.alma11` | Container RPM builder for AlmaLinux 11 (pre-release) |
| `packaging/rpm/build-rpm-container.sh` | Wrapper script: `-d alma{8,9,10,11} -v VERSION -o OUTDIR -e docker\|podman` |

---

## 7. Other new files

| File | Purpose |
|---|---|
| `BUILD_INSTALL.md` | End-user guide: build RPM → install → create test PKI → run minimal GSI `root://` server |
| `k8s-tests/pki-scripts/generate-jwt-keys.py` | Generate JWT signing key-pair for Keycloak replacement |
| `k8s-tests/test-infra-helm/templates/jwt-keys.yaml` | Kubernetes Secret for JWT keys |

---

## 8. Uncommitted working-tree deletions

The following files were present in the latest commit (`270e307`) but are
deleted in the current working tree (Keycloak removed in favour of JWT-based
OIDC):

- `k8s-tests/test-infra-helm/templates/keycloak-realm-init.yaml`
- `k8s-tests/test-infra-helm/templates/keycloak-secrets.yaml`
- `k8s-tests/test-infra-helm/templates/keycloak-service.yaml`
- `k8s-tests/test-infra-helm/templates/keycloak.yaml`

---

## 9. What is NOT changed relative to origin/main

- Core XRootD stream module entry point logic (`src/stream/module.c` exists but
  is a refactor destination, not net-new functionality)
- The `config` build file (minor: +1 line in commit `3ff2ca4`)
- `LICENSE`, `CONTRIBUTING.md`, `conftest.py` (root), `pytest.ini`,
  `requirements.txt`
- `tests/pki/` fixtures, `tests/nginx-bin` symlink

---

*Generated 12 May 2026 by comparing `HEAD` (270e307) and working tree against `origin/main` at `https://github.com/rob-c/nginx-xrootd.git`.*
