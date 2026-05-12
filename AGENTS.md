# AGENTS.md

AI agent orientation guide for `nginx-xrootd`. This file is organised so you
can skip directly to the section you need without exploring the codebase first.
Sections are ordered by how often agents need them.

---

## 0. Before You Touch Anything — Answer Three Questions

**Q1: Which protocol layer owns this request?**

| Client URL form | Layer | Handler entry point |
|---|---|---|
| `root://host//path` | `stream {}` raw TCP | `src/connection/handler.c` → `src/handshake/dispatch.c` |
| `roots://host//path` | `stream {}` SSL | same as above, TLS from byte 0 |
| `root://` + `xrootd_tls on` | `stream {}` in-protocol TLS upgrade | `src/session/protocol.c` → TLS negotiation → dispatch |
| `davs://` / `https://` WebDAV | `http {}` | `src/webdav/dispatch.c` → per-method handler |
| `http://` WebDAV (plain) | `http {}` | same as above, no TLS |
| S3 path-style REST | `http {}` | `src/s3/handler.c` → per-method handler |
| `/metrics` | `http {}` | `src/metrics/stream.c` or `writer.c` |

**Q2: What is the exact source file for the operation I am changing?**
→ See §4 "Operation-to-File Index".

**Q3: Which tests cover the behavior I am changing?**
→ See §5 "Test-to-Feature Map".

Answer all three before writing a single line of code.

---

## 1. Build Recipe (CRITICAL — Two Steps, Not One)

The nginx build system generates `objs/Makefile` from the `config` file during
`./configure`. Running `make` alone after editing `config` (e.g. adding a new
`.c` file) does **not** re-read `config`.

```bash
# Step 1 — always after editing the `config` file or adding new source files
cd /tmp/nginx-1.28.3          # or whichever nginx source tree you are using
./configure \
    --with-stream \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

# Step 2 — always
make -j$(nproc)
```

When to run `./configure` vs just `make`:

| Change | `./configure` needed? |
|---|---|
| Edit existing `.c` or `.h` | No — `make` is enough |
| Add a new `.c` file to `config` | **Yes** |
| Change the `config` file itself | **Yes** |
| Change nginx version | **Yes** |

RHEL/Alma dependency sketch (one-time setup):

```bash
sudo dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
    xrootd-client xrootd-server voms-libs curl python3 python3-pip
pip install pytest XRootD cryptography
```

See `docs/building.md` for TLS variants and additional nginx modules.

---

## 2. Test Runbook

### Starting and stopping test servers

```bash
tests/manage_test_servers.sh start    # starts nginx + reference xrootd
tests/manage_test_servers.sh status
tests/manage_test_servers.sh stop
```

### Running tests

```bash
# Run everything
PYTHONPATH=tests pytest tests/ -v

# Run a single file
PYTHONPATH=tests pytest tests/test_webdav.py -v

# Run a single class or test
PYTHONPATH=tests pytest tests/test_webdav.py::TestCopy -v
PYTHONPATH=tests pytest tests/test_webdav.py::TestCopy::test_copy_new_destination -v

# With timeout (recommended for protocol tests)
PYTHONPATH=tests pytest tests/test_aio.py -v --timeout=30
```

### Key test server ports

| Port | Protocol | Purpose |
|---:|---|---|
| 11094 | `root://` | anonymous nginx-xrootd |
| 11095 | `root://` | GSI nginx-xrootd |
| 11096 | `roots://` | GSI + stream TLS |
| 11097 | `root://` | bearer-token nginx-xrootd |
| 8443 | `davs://` | WebDAV over HTTPS |
| 8080 | `http://` | WebDAV plain HTTP |
| 9001 | HTTP | S3-style endpoint |
| 9100 | HTTP | Prometheus metrics |
| 11098 | `root://` | reference xrootd anonymous |
| 11099 | `root://` | reference xrootd GSI |

See `docs/testing/index.md` for the full list and per-test environment variables
(`TEST_NGINX_URL`, `TEST_REF_URL`, etc.).

### Cross-compatible tests (nginx-xrootd vs reference xrootd)

```bash
tests/run_cross_compatible_tests.sh
# uses TEST_CROSS_BACKEND=nginx and TEST_CROSS_BACKEND=xrootd
```

### Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` | `./tests/manage_test_servers.sh stop` or `pkill nginx` |
| GSI tests fail "certificate expired" | `rm -rf /tmp/xrd-test/pki` (forces regeneration) |
| `ModuleNotFoundError` in tests | `export PYTHONPATH=tests` |
| Conformance test fails | Check `error.log`; compare wire behavior with reference xrootd |

---

## 3. Project Overview

```text
                       nginx workers
                            |
      +---------------------+----------------------+
      |                                            |
  stream{}                                     http{}
      |                                            |
root:// / roots://        +------------------------+------------------+
      |                   |                        |                  |
native XRootD opcodes    WebDAV/HTTPS          S3-compatible      metrics
open/read/write/query    davs://, https://     path-style HTTP    /metrics
      |                   |                        |
      +-------------------+------------------------+
                          |
                   local POSIX files
```

`nginx-xrootd` is an nginx module for serving High Energy Physics (HEP) storage
workloads from local POSIX filesystems. It exposes the same on-disk data via
native XRootD wire protocol (`root://`), WebDAV (`davs://`/`https://`), and an
S3-compatible REST API — all in one nginx process.

---

## 4. Operation-to-File Index

The fastest path to the right file. For each protocol operation the file listed
is where the handler lives; supporting helpers are in the same or adjacent
directories.

### 4a. Native XRootD (stream layer)

**Session / connection lifecycle**

| Operation | Primary file |
|---|---|
| TCP accept, initial read loop | `src/connection/handler.c`, `src/connection/recv.c` |
| XRootD handshake framing | `src/handshake/dispatch.c` |
| `kXR_protocol` (version negotiation) | `src/session/protocol.c` |
| `kXR_login` | `src/session/login.c` |
| `kXR_auth` (GSI path) | `src/gsi/parse.c`, `src/gsi/cert_response.c` |
| `kXR_auth` (token/SSS dispatch) | `src/session/login.c` |
| `kXR_sigver` (request signing) | `src/handshake/sigver.c`, `src/session/signing.c` |
| `kXR_bind` (parallel streams) | `src/session/bind.c`, `src/session/registry.c` |
| `kXR_ping` / `kXR_endsess` | `src/handshake/dispatch_session.c` |
| `kXR_set` | `src/query/set.c` |
| Session opcode dispatch | `src/handshake/dispatch_session.c` |
| Read opcode dispatch | `src/handshake/dispatch_read.c` |
| Write opcode dispatch | `src/handshake/dispatch_write.c` |
| Policy checks (auth, write gate, scope) | `src/handshake/policy.c` |

**Reads**

| Operation | Primary file |
|---|---|
| `kXR_open` (read) | `src/read/open.c` |
| `kXR_open` (cache mode) | `src/read/open_cache.c` |
| `kXR_close` | `src/read/close.c` |
| `kXR_read` | `src/read/read.c`, `src/aio/read.c` |
| `kXR_readv` | `src/read/readv.c`, `src/aio/readv.c` |
| `kXR_pgread` | `src/read/pgread.c`, `src/aio/pgread.c` |
| `kXR_stat` / `kXR_statx` | `src/read/stat.c`, `src/read/statx.c` |
| `kXR_dirlist` | `src/dirlist/handler.c` |
| `kXR_locate` | `src/read/locate.c` |
| `kXR_clone` | `src/read/clone.c` |
| Prefetch / readahead | `src/read/prefetch.c` |
| AIO config and buffer pool | `src/aio/config.c`, `src/aio/buffers.c` |
| AIO write-back | `src/aio/write.c`, `src/aio/resume.c` |

**Writes and namespace**

| Operation | Primary file |
|---|---|
| `kXR_write` | `src/write/write.c` |
| `kXR_writev` | `src/write/writev.c` |
| `kXR_pgwrite` (with CRC32c verify) | `src/write/pgwrite.c` |
| `kXR_sync` | `src/write/sync.c` |
| `kXR_truncate` | `src/write/truncate.c` |
| `kXR_mkdir` | `src/write/mkdir.c` |
| `kXR_rm` | `src/write/rm.c` |
| `kXR_rmdir` | `src/write/rmdir.c` |
| `kXR_mv` | `src/write/mv.c` |
| `kXR_chmod` | `src/write/chmod.c` |
| `kXR_chkpoint` | `src/write/chkpoint.c`, `src/write/chkpoint_xeq.c` |
| Write common helpers | `src/write/common.c` |

**Extras**

| Operation | Primary file |
|---|---|
| `kXR_query` dispatch | `src/query/dispatch.c` |
| `kXR_query` checksum | `src/query/checksum.c` |
| `kXR_query` config | `src/query/config.c` |
| `kXR_query` space | `src/query/space.c` |
| `kXR_query` prepare staging | `src/query/prepare.c` |
| `kXR_query` metadata | `src/query/metadata.c` |
| `kXR_fattr` get/set/del | `src/fattr/get.c`, `src/fattr/set.c`, `src/fattr/del.c` |
| `kXR_prepare` | `src/query/prepare.c` |

**Native root:// TPC**

| Operation | Primary file |
|---|---|
| TPC key registry (shared memory) | `src/tpc/key_registry.c` |
| Destination: outbound pull client | `src/tpc/launch.c`, `src/tpc/thread.c` |
| Pull I/O loop | `src/tpc/io.c`, `src/tpc/source.c` |
| Pull bootstrap / GSI | `src/tpc/bootstrap.c`, `src/tpc/gsi_outbound.c` |
| Pull connection setup | `src/tpc/connect.c` |
| Pull completion | `src/tpc/done.c` |
| Token handling for TPC | `src/tpc/tpc_token.c` |
| kXR_clone (TPC fast-path) | `src/read/clone.c` |

**Manager / upstream / CMS**

| Operation | Primary file |
|---|---|
| Manager registry (dynamic state) | `src/manager/registry.c` |
| CMS heartbeat / space reporting | `src/cms/send.c` |
| CMS config | `src/cms/config.c` |
| Upstream/redirect handling | `src/upstream/` |

**Auth helpers (native layer)**

| Operation | Primary file |
|---|---|
| JWT/WLCG token validation | `src/token/validate.c` |
| Token scope checking | `src/token/scopes.c` |
| JWKS key loading | `src/token/jwks.c`, `src/token/keys.c` |
| Macaroon validation | `src/token/macaroon.c` |
| Token JSON/B64 helpers | `src/token/json.c`, `src/token/b64url.c` |
| GSI certificate parsing | `src/gsi/parse.c`, `src/gsi/buffer.c` |
| GSI config | `src/gsi/config.c` |
| SSS auth | `src/sss/` |
| PKI loading (shared) | `src/crypto/pki_load.c`, `src/crypto/pki_check.c` |
| VOMS VO extraction | `src/voms/` |

**Infrastructure**

| Concern | Primary file |
|---|---|
| Path resolution + confinement | `src/path/resolve.c` |
| Response builders | `src/response/` |
| Shared types / context structs | `src/types/` |
| Wire structs / opcodes / flags | `src/protocol/wire.h`, `src/protocol/opcodes.h`, `src/protocol/flags.h` |
| nginx directive parsing | `src/config/server_conf.c`, `src/config/postconfiguration.c` |
| nginx stream module entry point | `src/stream/` |
| Prometheus metrics (shared memory) | `src/metrics/metrics.h`, `src/metrics/stream.c` |
| Read-through cache | `src/cache/` |

### 4b. WebDAV (http layer)

| Operation | Primary file |
|---|---|
| Content handler entry point + method routing | `src/webdav/dispatch.c` |
| Upstream proxy forwarding (all methods) | `src/webdav/proxy.c` |
| OPTIONS (CORS, Allow header) | `src/webdav/methods_basic.c`, `src/webdav/cors.c` |
| GET (with Range, fd cache) | `src/webdav/get.c` |
| HEAD | `src/webdav/methods_basic.c` |
| PUT (body handler, spooled path) | `src/webdav/put.c` |
| DELETE | `src/webdav/namespace.c` |
| MKCOL | `src/webdav/namespace.c` |
| MOVE | `src/webdav/move.c` |
| COPY (RFC 4918 §9.8 server-side) | `src/webdav/copy.c` |
| COPY (HTTP-TPC pull, push) | `src/webdav/tpc.c`, `src/webdav/tpc_curl.c` |
| PROPFIND (XML response) | `src/webdav/propfind.c` |
| LOCK / UNLOCK | `src/webdav/lock.c` |
| LOCK enforcement (in PUT/MOVE/COPY) | `src/webdav/lock.c` (`webdav_check_locks`) |
| Auth: proxy certificate | `src/webdav/auth_cert.c`, `src/webdav/pki.c` |
| Auth: bearer token | `src/webdav/auth_token.c` |
| Auth credential store | `src/webdav/auth_store.c` |
| TPC credential delegation (oidc-agent, RFC 8693) | `src/webdav/tpc_cred.c` |
| TPC config (curl, cred mode) | `src/webdav/tpc_config.c` |
| TPC headers forwarding | `src/webdav/tpc_headers.c` |
| CORS header insertion | `src/webdav/cors.c` |
| HTTP response headers | `src/webdav/headers.c` |
| Date formatting | `src/webdav/date.c` |
| Path resolution + confinement (WebDAV) | `src/webdav/path.c` |
| Resource stat helpers | `src/webdav/resource.c` |
| I/O engine (copy_file_range + pread/write fallback) | `src/webdav/io.c` |
| Per-connection fd cache | `src/webdav/fd_cache.c` |
| Prometheus metrics (WebDAV) | `src/webdav/metrics.c`, `src/metrics/webdav.c` |
| nginx directive parsing (WebDAV) | `src/webdav/config.c`, `src/webdav/module.c` |
| Post-config (export root canonicalisation) | `src/webdav/postconfig.c` |
| Shared declarations (all WebDAV) | `src/webdav/webdav.h` |

**Dispatch order in `dispatch.c`** (critical — read before editing):

```
1. Auth gate (verify cert / token)
2. if conf->upstream_proxy → proxy.c  (all methods, no further dispatch)
3. Method routing:
   COPY with Source:                          → TPC pull   → tpc.c
   COPY with Destination: + Credential:       → TPC push   → tpc.c
   COPY with Destination: (no Credential:)    → server-side COPY → copy.c
   GET / HEAD / PUT / DELETE / MKCOL / MOVE / PROPFIND / LOCK / UNLOCK → per-method handlers
```

The proxy branch short-circuits everything after auth — if `upstream_proxy` is set, no method handler runs locally.

### 4c. S3 (http layer)

| Operation | Primary file |
|---|---|
| Content handler + routing | `src/s3/handler.c` |
| GET / HEAD | `src/s3/handler.c` |
| PUT (single-part) | `src/s3/put.c` |
| GET list (list-type=2) | `src/s3/list.c` |
| DELETE | `src/s3/handler.c` |
| CreateMultipartUpload (`POST ?uploads`) | `src/s3/multipart.c` |
| UploadPart (`PUT ?partNumber=N&uploadId=ID`) | `src/s3/handler.c` → `src/s3/put.c` |
| CompleteMultipartUpload (`POST ?uploadId=ID`) | `src/s3/multipart.c` |
| AbortMultipartUpload (`DELETE ?uploadId=ID`) | `src/s3/multipart.c` |
| SigV4 auth | `src/s3/auth.c` |
| XML/response utilities | `src/s3/util.c` |
| Prometheus metrics (S3) | `src/s3/metrics.c` |
| nginx directive parsing (S3) | `src/s3/module.c` |

---

## 5. Test-to-Feature Map

Go directly to the right test file without `grep`ing the test directory.

### Native XRootD protocol

| Feature / area | Test file |
|---|---|
| File open/read/close (basic) | `test_file_api.py` |
| Full xrootd protocol session | `test_xrootd.py` |
| AIO thread-pool read paths | `test_aio.py` |
| `kXR_readv` | `test_readv.py` |
| `kXR_pgread` + `kXR_pgwrite` CRC32c | `test_new_opcodes.py`, `test_pgwrite_checksum.py` |
| Writes: `kXR_write`, `kXR_truncate`, namespace | `test_write.py`, `test_fs_ops.py` |
| `kXR_query` subtypes | `test_query.py`, `test_query_extended.py` |
| `kXR_fattr` extended attributes | `test_fattr_query.py` |
| `kXR_prepare` staging | `test_prepare_staging.py` |
| `kXR_bind` parallel streams | `test_session_bind.py` |
| Concurrent requests | `test_concurrent.py` |
| I/O edge cases | `test_io_edge_cases.py` |
| Protocol edge cases | `test_protocol_edge_cases.py` |
| Opcode coverage (raw wire) | `test_opcode_coverage.py`, `test_opcode_flag_coverage.py` |
| GSI / proxy-cert auth | `test_gsi_tls.py`, `test_gsi_security.py`, `test_gsi_bridge.py` |
| Token (JWT/WLCG) auth | `test_token_auth.py`, `test_token_security.py` |
| Macaroon token auth | `test_token_macaroon.py` |
| VO / FQAN ACLs | `test_vo_acl.py` |
| CRL revocation | `test_crl.py` |
| `kXR_sigver` signing | `test_sigver_verify.py` |
| Security hardening (traversal, etc.) | `test_security_hardening.py` |
| Wire protocol security | `test_wire_protocol_security.py` |
| Privilege escalation | `test_privilege_escalation.py` |

### Native XRootD vs reference xrootd conformance

| Feature / area | Test file |
|---|---|
| Cross-backend conformance | `test_conformance.py` |
| xrdcp client compatibility | `test_xrdcp_client_options.py`, `test_xrdcp_root_anon_compare.py` |
| Robustness under load | `test_a_robustness.py` |
| Upstream redirect | `test_a_upstream_redirect.py` |

### Native root:// TPC

| Feature / area | Test file |
|---|---|
| Native TPC (source + dest roles, manager redirect) | `test_root_tpc.py` |

### WebDAV

| Feature / area | Test file |
|---|---|
| WebDAV functional (GET, PUT, DELETE, MKCOL, PROPFIND) | `test_webdav.py`, `test_http_webdav.py` |
| WebDAV status codes (comprehensive, HTTP) | `test_http_webdav_status_codes.py` |
| WebDAV status codes (comprehensive, HTTPS) | `test_https_webdav_status_codes.py` |
| WebDAV auth cache (proxy cert, bearer) | `test_webdav_auth_cache.py` |
| HTTP-TPC pull + push | `test_webdav_tpc.py` |
| HTTP-TPC SSRF policy | `test_tpc_ssrf_policy.py` |
| HTTP-TPC token mode | `test_tpc_token_mode.py` |
| TPC credential delegation (oidc-agent, token-exchange) | `test_webdav_tpc_cred.py` |
| WebDAV LOCK / UNLOCK | `test_http_webdav_lock.py` |
| WebDAV recursive LOCK | `test_http_webdav_lock_recursive.py` |
| WebDAV security (auth bypass, traversal) | `test_webdav_http_security.py` |
| WebDAV spooled PUT | `test_webdav_spooled_put.py` |
| WebDAV upstream proxy mode | `test_webdav_proxy.py` (pending) |
| Real WebDAV clients (davfs2, cadaver) | `test_a_webdav_clients.py` |

### S3

| Feature / area | Test file |
|---|---|
| S3 functional (GET, PUT, DELETE, list) | `test_s3.py` |
| S3 status codes | `test_s3_status_codes.py` |
| S3 multipart upload lifecycle | `test_s3_multipart.py` |

### Infrastructure

| Feature / area | Test file |
|---|---|
| Manager mode + CMS | `test_manager_mode.py`, `test_cms.py` |
| Prometheus metrics | `test_metrics.py` |
| Throughput benchmarks | `test_throughput.py` |

---

## 6. Implementation Recipes

Step-by-step for the most common tasks. Follow exactly — each step is load-bearing.

### Recipe A: Add a new WebDAV method (e.g. PATCH)

1. **Create** `src/webdav/patch.c` modelled on `src/webdav/copy.c` or `src/webdav/move.c`.
2. **Declare** the handler in `src/webdav/webdav.h` in the "HTTP methods" section:
   ```c
   ngx_int_t webdav_handle_patch(ngx_http_request_t *r);
   ```
3. **Add dispatch** in `src/webdav/dispatch.c` before the final `NGX_HTTP_NOT_ALLOWED` return:
   ```c
   if (r->method_name.len == 5
       && ngx_strncmp(r->method_name.data, "PATCH", 5) == 0)
   {
       if (!conf->allow_write) {
           return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
       }
       return webdav_metrics_return(r, webdav_handle_patch(r));
   }
   ```
4. **Update Allow header** in `src/webdav/methods_basic.c` — add "PATCH" to the
   `conf->allow_write` branch string.
5. **Add to `config`** — add `$ngx_addon_dir/src/webdav/patch.c \` after `move.c`.
6. **Re-run `./configure`** (see §1 Build Recipe — this is mandatory when adding `.c` files).
7. **Add tests** in both `tests/test_http_webdav_status_codes.py` and
   `tests/test_https_webdav_status_codes.py` — add a `_patch()` helper and a
   `TestPatch` class with at least: success (2xx), 403-without-write, 404-missing,
   405-wrong-method, and any security negative cases.

### Recipe B: Add a new native XRootD opcode handler

1. **Create** `src/<subsystem>/myop.c`. For a read-side op, use `src/read/` as the
   directory. For a write-side op, use `src/write/`. For queries, use `src/query/`.
2. **Add dispatch** in the appropriate dispatch file:
   - Read ops: `src/handshake/dispatch_read.c`
   - Write ops: `src/handshake/dispatch_write.c`
   - Session ops: `src/handshake/dispatch_session.c`
   - Query subtypes: `src/query/dispatch.c`
3. **Add opcode constant** in `src/protocol/opcodes.h` if new.
4. **Add wire struct** in `src/protocol/wire.h` if the request or response has a
   new fixed-size header.
5. **Add to `config`** — append `$ngx_addon_dir/src/<subsystem>/myop.c \`.
6. **Re-run `./configure`**.
7. **Add tests** in `tests/test_new_opcodes.py` or a dedicated file. Include
   positive path, error path (file not found, bad permissions), and at minimum one
   security negative test (path traversal or wrong scope).

### Recipe C: Add a new S3 API endpoint

1. **Add the handler** in `src/s3/multipart.c` (for multipart ops) or `src/s3/handler.c`
   (for simple ops), or create a new `src/s3/myop.c`.
2. **Add routing** in `src/s3/handler.c` — the main handler reads the query string
   and HTTP method to dispatch. Check for `?uploadId=`, `?uploads`, `?partNumber=`
   patterns already established there.
3. **Add to `config`** if a new `.c` file.
4. **Re-run `./configure`** if new `.c` added.
5. **Add tests** in `tests/test_s3_multipart.py` or `tests/test_s3_status_codes.py`.

### Recipe D: Add new Prometheus metrics

1. **Add metric enum** in `src/metrics/metrics.h` — follow the existing pattern for
   the relevant subsystem (webdav, s3, native).
2. **Add shared-memory field** in the metrics struct in `src/metrics/metrics_internal.h`.
3. **Add export** in the relevant writer (e.g. `src/metrics/webdav.c`) — add a
   `ngx_http_xrootd_metrics_emit_gauge` or `_counter` call.
4. **Increment** at the call site via the subsystem-specific macro (e.g.
   `XROOTD_WEBDAV_METRIC_INC(...)` in WebDAV code).
5. **Add a test assertion** in `tests/test_metrics.py`.

### Recipe E: Add a new nginx directive

1. **Declare** the directive in the `ngx_command_t` array in the module file
   (`src/webdav/module.c`, `src/s3/module.c`, or `src/config/server_conf.c`).
2. **Add the field** to the config struct in the corresponding `.h` file
   (`src/webdav/webdav.h`, `src/config/config.h`, etc.).
3. **Set a default** in the `*_create_loc_conf` or `*_create_srv_conf` function.
4. **Merge** in the `*_merge_loc_conf` or `*_merge_srv_conf` function.
5. **Document** in `docs/configuration/directives.md`.

---

## 7. Key API Quick Reference

These are the helpers most likely to appear in a new handler. Use them instead
of reimplementing equivalent logic.

### Path confinement (WebDAV)

```c
// Resolve request URI to absolute path; returns NGX_OK or HTTP error code.
// Prevents traversal — never bypass this.
ngx_int_t ngx_http_xrootd_webdav_resolve_path(
    ngx_http_request_t *r, const char *root_canon,
    char *out, size_t outsz);

// Resolve a Destination: header URL to absolute path.
// Used by COPY and MOVE — handles non-existent destinations via parent+filename.
ngx_int_t webdav_resolve_destination_path(
    ngx_log_t *log, const char *op_label, const char *root_canon,
    const char *decoded_path, char *out, size_t outsz);

// Confined open helpers (no path-traversal escape possible).
int xrootd_open_confined_canon(const char *root, const char *path, int flags, mode_t mode);
int xrootd_rename_confined_canon(const char *root, const char *src, const char *dst);
int xrootd_unlink_confined_canon(const char *root, const char *path);
int xrootd_link_confined_canon(const char *root, const char *oldp, const char *newp);
```

### Lock enforcement (WebDAV)

```c
// Check if path (or any member for depth-infinity) is locked by another token.
// write=1 for write-intent operations. Returns NGX_OK or NGX_HTTP_LOCKED (423).
ngx_int_t webdav_check_locks(ngx_http_request_t *r, const char *path, int write);
```

### Auth checks (WebDAV)

```c
// Verify proxy certificate from TLS client cert chain. Returns NGX_OK or error.
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

// Verify Authorization: Bearer token. Returns NGX_OK or error.
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

// Check that the verified token includes write scope for the given method.
// Returns NGX_OK or NGX_HTTP_FORBIDDEN.
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r, const char *method);
```

### Header helpers (WebDAV)

```c
// Find a request header by name (case-insensitive). Returns NULL if absent.
ngx_table_elt_t *webdav_tpc_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);

// Add CORS headers to the response (call before returning any status).
ngx_int_t webdav_add_cors_headers(ngx_http_request_t *r);
```

### Metrics (WebDAV)

```c
// Wrap the final return code to record the HTTP status in metrics.
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);

// Record that a request arrived (call once at handler entry).
void webdav_metrics_request(ngx_http_request_t *r);

// Increment a metric slot directly.
XROOTD_WEBDAV_METRIC_INC(slot_name);
```

### Per-connection fd cache (WebDAV)

```c
// Get or open a cached fd for path. Returns fd or -1.
int webdav_fd_table_get(webdav_fd_table_t *fdt, const char *path);

// Evict a cached fd after rename/overwrite so stale fds are not reused.
void webdav_fd_table_evict(webdav_fd_table_t *fdt, const char *path);
```

### I/O engine (WebDAV copy_file_range + pread/write fallback)

```c
// Copy src_fd → dst_fd. Uses copy_file_range(2) then falls back to pread/write.
// scratch must be caller-allocated (1 MB from r->pool). Returns 0 on success.
int webdav_copy_fds(ngx_log_t *log, int src_fd, int dst_fd,
    off_t src_size, const char *dst_path, char *scratch);
```

### Token scope checks (native layer)

```c
// Check that the session token allows the given access mode at the given path.
// access_mode: XROOTD_TOKEN_READ, XROOTD_TOKEN_WRITE, XROOTD_TOKEN_CREATE.
ngx_int_t xrootd_token_check_scope(xrootd_session_t *sess,
    const char *path, int access_mode);
```

---

## 8. Disambiguation Patterns

Patterns that are easy to get wrong — read before touching the relevant code.

### TPC push vs server-side COPY (dispatch.c)

Standard WebDAV COPY (RFC 4918 §9.8, `copy.c`) and WLCG HTTP-TPC push (`tpc.c`)
both arrive as `COPY` with a `Destination:` header. The distinguisher is:

- `Credential:` header present → **TPC push** (route to `tpc.c`)
- `Source:` header present → **TPC pull** (route to `tpc.c`)
- Neither → **server-side copy** (route to `copy.c`)

Do not use the scheme of the Destination URL (`https://`) as the signal.
TPC can be disabled (`conf->tpc == 0`) even when the destination is a remote URL,
and the server-side COPY handler correctly returns 412/404/etc. for local paths.

### pgread response framing

`kXR_pgread` uses `kXR_status` (opcode 4007) as its response, **not** `kXR_ok`.
Data pages include per-page CRC32c in a specific wire layout. Do not use the
standard `xrootd_build_chunked_chain()` response builder for pgread.

### kXR_read vs kXR_pgread buffer paths

`kXR_read` can use file-backed nginx buffers (sendfile-style) on cleartext paths.
`kXR_pgread` and all TLS paths must use memory-backed responses. Mixing them
causes silent data corruption or sendfile errors on TLS connections.

### WebDAV auth=optional vs auth=none

`auth=optional` still attempts verification; anonymous access is allowed if
both proxy cert and bearer token verification fail. `auth=none` skips
verification entirely and emits a different metric slot. The distinction matters
for metrics and for downstream log analysis.

### Native write gate

`xrootd_allow_write` is a server-wide write gate independent of token scopes.
Even with a valid `storage.write` token, writes fail if the gate is off. Check
`conf->allow_write` before token scope in all write handler dispatch paths.

### S3 multipart upload staging

Multipart parts are stored as `.<key>.mpu-<id>/part.<N>` alongside the target
object. `CompleteMultipartUpload` assembles them in ascending part-number order
into a temp file, then atomically renames. Part numbers are validated 1–10000
before appearing in any path. All filesystem access goes through confined-open
helpers.

---

## 9. Protocol Invariants and Sharp Edges

| Area | Rule |
|---|---|
| `kXR_pgread` | Final response is `kXR_status` (4007), not `kXR_ok`; data has per-page CRC32c in specific wire layout. |
| `kXR_read` | Uses normal read response framing; may use file-backed nginx buffers on cleartext only. |
| `kXR_pgwrite` | Must verify CRC32c page fields, strip them, and write raw file bytes. |
| `kXR_readv` | Must preserve XRootD vector response layout; coalesce only when wire semantics are identical. |
| `kXR_bind` | Bound secondaries may only read (no open/write/stat/etc.); primary is the control channel. |
| `kXR_sigver` | GSI sessions derive HMAC signing state from the GSI exchange; sequence numbers must strictly increase. |
| Token scopes | Path-resolving operations enforce `storage.read`, `storage.write`, or `storage.create`; handle I/O inherits the open-time decision. |
| Write gate | `xrootd_allow_write` gates all writes server-wide, independent of token scopes. |
| TLS | File-backed sendfile paths are for cleartext only; TLS paths require memory-backed responses. |
| Path confinement | Never bypass canonical root checks; always use the confined-open helpers. |
| WebDAV collections | Operations that overwrite or delete collections (DELETE, MOVE, COPY) MUST recursively check member locks. |
| S3 auth | SigV4 is separate from WLCG JWT auth; never mix them in the same code path. |

When in doubt, compare with reference xrootd before changing wire-visible
semantics.

---

## 10. Performance Model and Hot Paths

nginx workers must not block on slow operations. Disk I/O either stays small and
obviously safe or goes through nginx thread pools.

Important hot-path optimizations already in place (do not undo):

- Cleartext `kXR_read` uses file-backed `ngx_buf_t` chains and nginx sendfile path.
- One-chunk read chains are reused to reduce per-read allocation.
- Read-only handles cache file size and stat metadata.
- Sequential reads use stateful readahead (not `posix_fadvise()` per request).
- TLS memory-backed reads reuse AIO task/scratch state where safe.
- `kXR_readv` packs directly into the final wire layout; batches adjacent ranges with `preadv()`.
- Send path uses posted continuations to avoid extra event wakeups.
- WebDAV GET pre-resolves the export root and uses a per-connection fd cache.
- WebDAV PUT detects nginx-spooled request bodies and uses kernel-side copy.
- WebDAV x509 verification caches reuse across keepalive/resumed TLS requests.
- Token auth is local (JWKS from disk); no per-request IdP network call.
- Metrics use shared atomic counters.

Read `docs/optimizations/index.md` (and the relevant sub-page) before touching read, send, WebDAV GET/PUT, auth
cache, or metrics code. Sub-pages: `native-read.md`, `pgread-write.md`, `webdav.md`, `auth.md`.

---

## 11. Code Style Requirements

Code must be easy to audit. This is a correctness requirement because most bugs
in C come from misreading ownership, lengths, or which buffer a pointer refers to.

Default to the simplest implementation within ~90% of the clever version's
performance. Use the clever version only when the benefit is measured.

**Avoid:**

- Compressed one-liners that hide control flow
- Generic names (`p`, `q`, `n`, `len`, `buf`) outside tiny local loops
- Macros that perform validation, allocation, or returns where a helper suffices
- Manual pointer walking without named cursor/start/end/length variables
- Ownership transfer implied by convention rather than parameter name

**Prefer:** Small helpers with descriptive names, early returns, explicit units
(`_bytes`, `_offset`, `_status`), and short comments explaining non-obvious
protocol rules or lifetime constraints.

**Comments:** Default to none. Add one only when the WHY is non-obvious (a
hidden constraint, a protocol workaround, a subtle invariant). Never describe
WHAT the code does — well-named identifiers do that. Never reference the current
task, PR, or caller in comments.

---

## 12. Authentication and Authorization Notes

### Native XRootD layer

- Anonymous: `xrootd_auth none`
- GSI/x509 proxy certs: `xrootd_auth gsi` → `src/gsi/`
- JWT/WLCG bearer tokens: `xrootd_auth token` → `src/token/`
- Macaroon tokens: dispatched from `src/token/validate.c` → `src/token/macaroon.c`
- Mixed: `xrootd_auth both`
- SSS: `src/sss/`

### WebDAV layer (independent of native auth)

- Proxy certificate: `src/webdav/auth_cert.c` (TLS client cert, VOMS)
- Bearer token: `src/webdav/auth_token.c`
- Policy: `auth=required` / `auth=optional` / `auth=none` via directive
- TPC credential delegation: `src/webdav/tpc_cred.c` (oidc-agent, RFC 8693 token exchange)
- Upstream proxy auth policy (`xrootd_webdav_proxy_auth`): `anonymous` strips Authorization, `forward` passes it through, `token <val>` replaces it with a static Bearer token — configured in `src/webdav/module.c`, applied in `src/webdav/proxy.c`

### Authorization sources

- GSI subject DN
- VOMS VO/FQAN attributes (`src/voms/`)
- Token `sub` / `wlcg.groups`
- Token storage scopes (`storage.read`, `storage.write`, `storage.create`)
- Configured `xrootd_require_vo`
- Filesystem permissions + server-wide write gate

Grid security layering: transport TLS, identity proof, VO membership, and path
authorization are separate layers. See `docs/pki/index.md` and `docs/authentication.md`.

---

## 13. Source Tree Guide

| Directory | Purpose |
|---|---|
| `src/aio/` | nginx thread-pool I/O helpers and AIO completion callbacks |
| `src/cache/` | Read-through cache mode |
| `src/cms/` | CMS manager heartbeat and space/load reporting |
| `src/config/` | nginx directive parsing and runtime server config |
| `src/connection/` | TCP connection lifecycle, receive/send events, fd table |
| `src/crypto/` | Shared crypto/PKI loading and verification helpers |
| `src/dirlist/` | Native directory listing |
| `src/fattr/` | Extended attribute operations |
| `src/gsi/` | Native XRootD GSI/x509 authentication |
| `src/handshake/` | XRootD handshake, dispatch, policy checks, sigver |
| `src/manager/` | Dynamic manager/registry state |
| `src/metrics/` | Prometheus shared-memory counters |
| `src/path/` | Path resolution, confinement, ACLs, access logging |
| `src/protocol/` | Opcodes, flags, primitive types, packed wire structs |
| `src/query/` | `kXR_query` subtypes: checksum, config, stats, xattrs, prepare |
| `src/read/` | Native read-side: open/read/readv/pgread/stat/locate/clone |
| `src/response/` | Response builders, CRC32c, common send helpers |
| `src/s3/` | S3-compatible HTTP endpoint |
| `src/session/` | Login, auth dispatch, protocol negotiation, bind, TLS flags |
| `src/sss/` | SSS authentication |
| `src/stream/` | nginx stream module entry point |
| `src/token/` | JWT/WLCG/Macaroon bearer-token validation and scope checks |
| `src/tpc/` | Native root:// third-party copy |
| `src/types/` | Shared context/config/file/tunable structs |
| `src/upstream/` | Redirector/upstream forwarding |
| `src/voms/` | VOMS VO extraction and ACL support |
| `src/webdav/` | WebDAV HTTP module (all methods, auth, TPC, fd cache, metrics) |
| `src/write/` | Native write-side: write/writev/pgwrite/sync/truncate/mkdir/rm/mv/chmod |

Key wire reference headers:

- `src/protocol/opcodes.h` — XRootD opcode constants
- `src/protocol/wire.h` — packed request/response structs
- `src/protocol/flags.h` — open/stat/locate flags
- `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` — reference (when available)

---

## 14. Documentation Map

Read the relevant doc before making nontrivial changes to the covered area.

| Need | Read |
|---|---|
| Newcomer overview | `README.md`, `docs/background.md` |
| Request lifecycle and code-path diagrams | `docs/architecture/index.md` → `stream.md`, `webdav.md`, `s3.md` |
| Supported XRootD operations and status | `docs/operations/index.md` → `read.md`, `write.md`, `management.md`; `docs/status.md` |
| Feature roadmap | `docs/feature-roadmap.md` |
| Client behavior from `xrdcp` | `docs/xrdcp-interactions.md` |
| Configuration directives | `docs/configuration/directives.md` (full ref), `docs/configuration/quick-reference.md` (tables) |
| Authentication setup | `docs/authentication.md` |
| Grid/WLCG/OSG PKI, VOMS, proxy certs | `docs/pki/index.md` → `certificates.md`, `gsi-auth.md`, `authorization.md` |
| TLS modes | `docs/tls.md` |
| WebDAV method behavior and RFC compliance | `docs/webdav/index.md` → `directives.md`, `methods.md`, `tpc.md` |
| Performance work and hot paths | `docs/optimizations/index.md` → `native-read.md`, `webdav.md`, `auth.md` |
| Manager/cluster behavior | `docs/manager-mode.md`, `docs/cluster-mode.md` |
| Test harness, ports, PKI fixtures | `docs/testing/index.md`, `docs/testing/infrastructure.md` |
| Development workflow | `docs/development.md`, `docs/contributing/index.md` → `extending.md`, `code-style.md`, `worked-examples.md` |
| Wire/protocol quirks | `docs/protocol-notes.md`, `docs/quirks.md` |
| Core types | `docs/types.md` |
| Metrics export format | `docs/metrics-and-logging.md` |
| Getting started guide | `docs/getting-started.md` |
| Handler function reference | `docs/handler-reference.md` |
| TPC comparison | `docs/tpc-comparison.md` |
| Comparison with reference xrootd | `docs/comparison/index.md` → `by-the-numbers.md`, `design-rationale.md`, `deployment-guide.md` |

---

## 15. Common Debugging Patterns

| Symptom | First places to check |
|---|---|
| Native request fails before file access | `src/connection/recv.c`, `src/handshake/dispatch*.c`, `src/session/` |
| `root://` auth issue | `src/gsi/`, `src/token/`, `src/session/login.c`, `docs/authentication.md` |
| `davs://` x509 issue | nginx SSL config, `src/webdav/auth_cert.c`, `docs/tls.md`, `docs/pki/gsi-auth.md` |
| Token scope surprise | `src/token/scopes.c`, `src/handshake/policy.c`, `docs/authentication.md` |
| Read throughput regression | `src/read/`, `src/aio/`, `src/connection/send.c`, `docs/optimizations/native-read.md` |
| WebDAV GET syscall regression | `src/webdav/fd_cache.c`, `src/webdav/get.c` |
| WebDAV COPY/MOVE wrong route | `src/webdav/dispatch.c` — check Credential:/Source:/Destination: header presence |
| WebDAV proxy not forwarding | `src/webdav/dispatch.c` — confirm `conf->upstream_proxy` is set; `src/webdav/proxy.c` — check `create_request` / `process_header` callbacks |
| WebDAV proxy Destination header wrong | `src/webdav/proxy.c` `webdav_proxy_rewrite_destination()` — strips public scheme+host, prepends upstream_url_base |
| S3 endpoint issue | `src/s3/handler.c`, `tests/test_s3.py`, `tests/test_s3_status_codes.py` |
| S3 multipart issue | `src/s3/multipart.c`, `tests/test_s3_multipart.py` |
| Reference mismatch | `tests/test_conformance.py`, `tests/run_cross_compatible_tests.sh` |
| Path traversal / security failure | `src/path/resolve.c`, confined open helpers, `tests/test_security_hardening.py` |
| Metrics counter wrong | `src/metrics/`, subsystem `metrics.c`, `tests/test_metrics.py` |

Access logs and protocol dumps are more useful than guessing. For wire-visible
native behavior, compare nginx-xrootd with reference xrootd before changing
response codes, status bodies, or framing.

---

## 16. Agent Workflow Expectations

1. Answer §0's three questions before writing any code.
2. Read the relevant doc from §14 before making nontrivial changes.
3. Use §6's recipes for common tasks — do not explore when a recipe exists.
4. Keep the code style requirements in §11 in force for all changes.
5. Use existing helper APIs (§7) for path confinement, response building, auth,
   metrics, and logging — do not reimplement.
6. Preserve protocol conformance when optimising; reference xrootd is the
   tie-breaker for native wire behavior.
7. When touching user-visible behavior, update docs and tests in the same change.
8. When adding tests: cover the success path, the main error paths, and at least
   one security negative case (traversal, missing auth, wrong scope, bad input).
   All tests must be deterministic — no timing-dependent assertions.
9. Any change touching auth, TLS, token handling, path resolution, or
   data-exposing logic is security-sensitive: add mandatory negative tests.
10. Do not revert unrelated working-tree changes. This repository is often dirty
    during agent sessions.

---

## 17. Common Pitfalls

- Do not use `xrootd_build_chunked_chain()` for `kXR_pgread` — pgread has its
  own `kXR_status` response shape and per-page CRC encoding.
- Do not assume GSI encrypts the whole native data stream. Use `roots://` or
  `xrootd_tls on` for transport encryption.
- Do not assume WebDAV and native XRootD share auth code — they verify similar
  credentials in different nginx layers.
- Do not treat S3 SigV4 auth as WLCG token auth.
- Do not add a pathname syscall to every read request — the cached handle
  metadata already has stat results.
- Do not bypass write gates or token scopes when reusing open handles.
- Do not add noisy per-request INFO logs on hot keepalive paths.
- Do not use file-backed buffers for TLS paths unless explicitly tested.
- Do not dispatch TPC push based on `https://` scheme in the Destination URL —
  use the `Credential:` header (§8 Disambiguation Patterns).
- Do not add per-method dispatch logic after the proxy check in `dispatch.c` —
  when `conf->upstream_proxy` is set the entire request is forwarded; method
  handlers must not run locally.
- Do not run only `make` after editing `config` or adding a `.c` file — run
  `./configure` first (§1 Build Recipe).
- Do not add S3 bucket, key, or access-key labels to Prometheus metrics —
  unbounded cardinality.
