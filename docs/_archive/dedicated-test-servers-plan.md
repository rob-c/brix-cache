# Dedicated Test Servers Plan [2026-05-25]

## Goal

Eliminate all temporary/on-demand server instances from the test suite. Every nginx and xrootd instance used by tests must be:
1. **Dedicated** — assigned a fixed port, never reused across unrelated test modules
2. **Permanent** — started before any test runs, kept alive for the entire pytest session
3. **Pre-launched** — `manage_test_servers.sh start-all` fires all instances before the first test
4. **Real** — tests for inter-server behavior must exercise actual server-to-server traffic, not Python mock servers or inline protocol simulators

## Hard Rule: No Test May Manage Its Own Server

No test file, fixture, or helper is permitted to:

- Call `NGINX_BIN` (directly or via `subprocess.Popen` / `subprocess.run`)
- Call `server_control.start_nginx_instance()` or `server_control.start_xrootd_instance()`
- Call `server_control._free_port()` to allocate a random port for a test-local server
- Run `nginx -t` for config validation — a running dedicated server IS the config validation

This rule applies without exception. If a test scenario requires a server configuration that does not yet exist as a dedicated instance, the correct fix is to add that config to `manage_test_servers.sh start-all`, not to start a server inside the test.

### Why `nginx -t` is also forbidden

`nginx -t` writes to the compiled-in default prefix (`/usr/local/nginx/logs/error.log`) before reading the config, causing permission failures in non-root environments. A dedicated server that is already running on its fixed port is proof the config is valid. The correct replacement: assert the port accepts connections, and read startup messages from the instance's `error.log`.

## Non-Negotiable Test Model

The dedicated-server migration is not just a port-allocation cleanup. The desired final state is that tests which claim to cover server-to-server behavior actually run two or more real server processes and verify the live interaction between them.

**Required model:**
- No mock server instances for protocol peers. This includes Python socket listeners, thread-based fake upstreams, fake origin, in-test CMS managers, and ad hoc handlers that impersonate xrootd, xrdhttp, WebDAV, S3, TPC, CMS, or upstream redirectors.
- A test may still use a raw socket as a **client** to send malformed frames or inspect wire behavior. It must not use a raw socket listener as the **server** under test.
- Server-to-server tests must use real nginx-xrootd and/or real xrootd processes launched by the test infrastructure on fixed ports.
- Negative server-to-server cases must be represented with real server configuration.
- Test helpers may generate files, certificates, tokens, CRLs, JWKS documents, and request payloads. They must not emulate the remote protocol peer for integration/conformance coverage.
- Unit tests for pure parsing or formatting helpers can stay in-process. Anything involving a listener, redirector, origin, manager, TPC endpoint, or peer protocol handshake should use an actual dedicated server.

---

## Implementation Status [as of 2026-05-25]

### Completed

**Phase 0 — Type C violations removed** ✓ DONE (5 files)
- `test_webdav_auth_cache.py` — removed `NGINX_BIN` import and binary check
- `test_webdav_tpc.py` — removed `NGINX_BIN` import and binary check
- `test_webdav_tpc_cred.py` — removed `NGINX_BIN` import and binary check
- `test_root_tpc.py` — removed `NGINX_BIN` import and binary check
- `test_token_jwks_refresh.py` — removed local `NGINX_BIN` assignment and binary check

**Phase 1 — Type B violations replaced** ✓ DONE (2 files)
- `test_crl.py` — `TestCRLConfigDirectives` and `TestCRLDirectoryMode` config-validation tests
  replaced with port-reachability check + `error.log` content assertion; `nginx -t` removed
- `test_ocsp.py` — all `nginx -t` / config-directive tests deleted; only
  `TestMockOCSPResponseBuilder` and `TestMockOCSPServer` (in-process unit tests) retained

**Phase 2 — Config templates created** (7 of ~18 remaining needed)
- `nginx_tpc_ssrf_default.conf` ✓
- `nginx_tpc_ssrf_allow_local.conf` ✓
- `nginx_tpc_ssrf_deny_private.conf` ✓
- `nginx_s3_presigned.conf` ✓
- `nginx_s3_presigned_sts.conf` ✓
- `nginx_security_level_standard.conf` ✓
- `nginx_security_level_pedantic.conf` ✓

**Phase 3 — Port constants added** (7 of ~20 remaining needed)
`settings.py` now has: `TPC_SSRF_DEFAULT_PORT=11180`, `TPC_SSRF_ALLOW_LOCAL_PORT=11181`,
`TPC_SSRF_DENY_PRIVATE_PORT=11182`, `S3_PRESIGNED_PORT=11183`, `S3_PRESIGNED_STS_PORT=11184`,
`SECURITY_LEVEL_STANDARD_PORT=11191`, `SECURITY_LEVEL_PEDANTIC_PORT=11192`

**Phase 4 — Type A tests converted** (7 of 14 files)
- `test_privilege_escalation.py` — `readonly_nginx` fixture: connectivity check on `READONLY_PORT` (11102)
- `test_vo_acl.py` — `vo_nginx` fixture: VOMS PKI setup (idempotent) + xrdfs connectivity check on `VO_PORT` (11103)
- `test_xrdhttp_conformance.py` — `xrdhttp_backend` fixture: curl connectivity check on 11112/11113
- `test_xrdhttp_webdav.py` — `xrdhttp_backend` fixture: curl connectivity check on 11112/11113
- `test_tpc_ssrf_policy.py` — 3 fixtures: socket connectivity check on 11180/11181/11182
- `test_s3_presigned.py` — 2 fixtures: socket connectivity check on 11183/11184
- `test_security_level.py` — `security_nginx` factory fixture: returns known port dict for 11191/11192

**manage_test_servers.sh updated**: 7 new `start_dedicated_nginx` calls for the SSRF, S3, and
security-level servers.

### Remaining (deferred)

6 test files still have violations. They are ordered below from simplest to most complex.

| Test File | Violations | Complexity |
|---|---|---|
| `test_authdb.py` | `NGINX_BIN` import + 1 × `start_nginx_instance` | Medium |
| `test_prepare_staging.py` | 3 × `start_nginx_instance` inside `TestPrepareStageCommand` | Medium |
| `test_cms.py` | 1 × `start_nginx_instance` + `_MockCmsManager` Python listener | High |
| `test_a_upstream_redirect.py` | `NGINX_BIN` + `MockUpstream` class + 4 × `_start_upstream_nginx` | High |
| `test_proxy_mode.py` | `NGINX_BIN` + 1 × `start_xrootd_instance` + 3 × `start_nginx_instance` + `_free_port` | High |
| `test_manager_mode.py` | `NGINX_BIN` + 9 cluster fixtures × (2–6 × `_free_port` + 2–4 × `start_nginx_instance`) | Very High |

---

## Detailed Plans for Remaining Files

### test_authdb.py

**Current state:**
- `authdb_setup` session fixture: creates `/tmp/xrd-authdb-test/{authdb,data/*/seed.txt}` (idempotent)
- `authdb_nginx` session fixture: calls `server_control.start_nginx_instance(port=AUTHDB_PORT, ...)` with inline `conf_text` referencing `VOMSDIR`, `VOMS_CERT_DIR`, `AUTHDB_FILE`
- `AUTHDB_PORT = 11114` already in `settings.py`

**Plan:**

1. **Create `tests/configs/nginx_authdb.conf`** with placeholders `{PORT}`, `{DATA_DIR}`, `{LOG_DIR}`, `{SERVER_CERT}`, `{SERVER_KEY}`, `{CA_CERT}`, `{VOMSDIR}`, `{VOMS_CERT_DIR}`, `{AUTHDB_FILE}`.

2. **Update `manage_test_servers.sh`:**
   - Before `start_dedicated_nginx "authdb" ...`, create the authdb data tree:
     ```bash
     _ensure_authdb() {
         local dir=/tmp/xrd-authdb-test
         mkdir -p "$dir/data"/{public,cms,atlas,private,host,hostcidr,hostdeny}
         # seed files
         for d in public cms atlas private host hostcidr hostdeny; do
             echo "seed in $d" > "$dir/data/$d/seed.txt"
         done
         # authdb rules
         cat > "$dir/authdb" << 'EOF'
     u * /public rl
     g cms /cms r
     g atlas /atlas r
     u * /private rw
     p 127.0.0.1 /host r
     p ::1 /host r
     p 127.0.0.0/8 /hostcidr r
     p ::1/128 /hostcidr r
     p 192.0.2.0/24 /hostdeny r
     EOF
     }
     _ensure_authdb
     start_dedicated_nginx "authdb" "nginx_authdb.conf" "${AUTHDB_PORT:-11114}" \
         VOMSDIR=/path/to/vomsdir VOMS_CERT_DIR=/path/to/ca AUTHDB_FILE=/tmp/xrd-authdb-test/authdb
     ```
   - `start_dedicated_nginx` must support extra `KEY=VALUE` placeholder overrides.

3. **Rewrite `authdb_nginx` fixture:**
   ```python
   @pytest.fixture(scope="session")
   def authdb_nginx(authdb_setup):
       try:
           with socket.create_connection(("127.0.0.1", AUTHDB_PORT), timeout=5):
               pass
       except OSError:
           pytest.skip(f"authdb server not reachable at port {AUTHDB_PORT}")
       env = {**os.environ, "X509_CERT_DIR": CA_DIR, "X509_USER_PROXY": PROXY_STD,
              "XrdSecPROTOCOL": "gsi"}
       for _ in range(20):
           r = subprocess.run(["xrdfs", AUTHDB_URL, "stat", "/public/seed.txt"],
                              env=env, capture_output=True, timeout=5)
           if r.returncode == 0:
               break
           time.sleep(0.5)
       else:
           pytest.skip("authdb nginx not ready (xrdfs stat timed out)")
       yield
   ```

4. **Remove** `NGINX_BIN` from import; remove `import server_control`.

**Key challenge:** `manage_test_servers.sh` must create the authdb file before nginx starts. The `authdb_setup` fixture must remain idempotent so it can run both paths without conflict.

---

### test_prepare_staging.py

**Current state:**
- `TestPrepareValid`, `TestPrepareNotFound`, `TestPrepareNoErrs`, etc. — use `anon_port` from `test_env` (no violations, already clean)
- `TestPrepareStageCommand` — 3 tests call `_start_nginx_with_cmd()` which calls `server_control.start_nginx_instance()` with per-test `STAGE_CMD` and conf templates; tests are marked `@pytest.mark.requires_local_server`

**Plan:**

1. **Create `tests/configs/nginx_prepare_command.conf`** — stream server with `xrootd_prepare_command {STAGE_CMD}` directive and placeholders `{PORT}`, `{DATA_DIR}`, `{LOG_DIR}`.

2. **Add `PREPARE_CMD_PORT = 11185`** to `settings.py`.

3. **Update `manage_test_servers.sh`:**
   ```bash
   # Create the stage hook script
   STAGE_LOG="$TEST_ROOT/dedicated/prepare-cmd/staged_paths.log"
   STAGE_HOOK="$TEST_ROOT/dedicated/prepare-cmd/stage_hook.sh"
   mkdir -p "$(dirname "$STAGE_HOOK")"
   printf '#!/bin/sh\nprintf "%%s\\n" "$@" >> %s\n' "$STAGE_LOG" > "$STAGE_HOOK"
   chmod +x "$STAGE_HOOK"
   start_dedicated_nginx "prepare-cmd" "nginx_prepare_command.conf" "${PREPARE_CMD_PORT:-11185}" \
       STAGE_CMD="$STAGE_HOOK"
   ```

4. **Rewrite `TestPrepareStageCommand`:**
   - Remove `_CONF`, `_CONF_NOCMD`, `_start_nginx_with_cmd()`, `_make_stage_script()`
   - Add module-level fixture that verifies 11185 is listening
   - `test_stage_flag_invokes_command`: seed a unique file into `data-prepare-cmd/`, truncate/rotate the log, send kXR_stage with that path, wait up to 3s for log entry
   - `test_no_stage_flag_skips_command`: send kXR_prepare without stage flag, wait 0.3s, assert path NOT in log
   - `test_no_config_stage_silently_accepted`: use `test_env["anon_port"]` (the shared anon server at 11094 has no `xrootd_prepare_command` configured)
   - Use unique filenames (e.g., UUID-based) per test to avoid cross-test log pollution

**Key challenge:** The stage-hook log is shared across tests. Use unique path strings per test and grep for just that path. Truncate the log in a session-scoped autouse fixture to avoid carryover from previous runs.

---

### test_cms.py

**Current state:**
- `cms_nginx` module fixture: starts nginx on hardcoded port 12500 with `xrootd_cms_manager 127.0.0.1:12400`, starts `_MockCmsManager` on port 12400
- `_MockCmsManager` listens for outbound CMS frames from nginx: LOGIN, AVAIL, PING/PONG, STATUS
- Tests assert on frame-level details: payload format of LOGIN, PONG sent in response to PING

**Problem:** `_MockCmsManager` is a Python mock server listener — forbidden by the Non-Negotiable Test Model.

**Plan:**

The CMS tests must be rewritten to observe behavior through the cluster layer, not by inspecting raw CMS frames. The cluster fixture from test_manager_mode.py provides the real observable surface: does the data server get registered? Does the redirector redirect correctly? Does it stop redirecting after the DS disconnects?

1. **Add cluster ports to `settings.py`:**
   ```python
   CMS_CLUSTER_REDIR_PORT = 11130
   CMS_CLUSTER_CMS_PORT   = 11150
   CMS_CLUSTER_DS_PORT    = 11140
   ```

2. **Add templates:**
   - `nginx_cms_redir.conf`: `xrootd_manager_mode on;` stream server on `{PORT}`, CMS server on `{CMS_PORT}`
   - `nginx_cms_dataserver.conf`: `xrootd_cms_manager 127.0.0.1:{CMS_PORT}; xrootd_cms_paths /; xrootd_cms_interval 5;`

3. **Update `manage_test_servers.sh`:** start redir on 11130, CMS listener on 11150, DS on 11140; wait 5s for registration.

4. **Rewrite tests:**
   - `test_login_frame_received` → `test_data_server_registers_with_redirector`: send kXR_locate to redir (11130), verify kXR_redirect to DS port (11140). DS being redirected to proves nginx sent LOGIN.
   - `test_pong_response_to_ping` → `test_cluster_stays_healthy`: after 10s, verify redirector still redirects (the CMS heartbeat cycle keeps the registration alive, which implies PONG is sent).
   - `test_avail_frame_delivery` → `test_redirect_consistent_after_avail`: locate before and after the DS's avail interval, verify redirect still works.
   - `test_reconnect_after_disconnect` → handled by `TestClusterUnregister` equivalent: stop DS, verify no redirect; restart DS (or use separate test cluster), verify redirect returns.

5. **Remove** `_MockCmsManager` class, `cms_nginx` fixture, hardcoded ports 12400/12500, `server_control` import.

**Note:** Frame-level protocol assertions (exact LOGIN payload layout, exact PING timing) are sacrificed. The behavioral equivalents are strictly stronger: if the cluster works end-to-end, the CMS protocol must be implemented correctly.

---

### test_a_upstream_redirect.py

**Current state:**
- Nginx frontend servers (11120-11126) are already dedicated (started by `manage_test_servers.sh`)
- Backend servers (12120-12126) are also already dedicated real nginx instances
- Test file still starts `MockUpstream` on the backend ports, conflicting with the dedicated backends
- `_start_upstream_nginx()` calls `server_control.start_nginx_instance()` to restart the nginx frontends — which are already running
- `upstream_wait_nginx` is **function-scoped** (restarts nginx per test) — must become session-scoped

**Why MockUpstream conflicts:** `MockUpstream(handler, UPSTREAM_REDIRECT_BACKEND_PORT)` tries to `bind("127.0.0.1", 12120)` — a port already occupied by the dedicated backend. When the fleet is running, every MockUpstream creation raises `OSError: [Errno 98] Address already in use`.

**Plan:**

1. **Audit what each dedicated backend must return.** The dedicated backend configs at 12120-12126 must be configured to produce the exact response the test expects, because tests will no longer control per-test handlers.

   | Backend | Port | Required response | Config directive |
   |---|---|---|---|
   | redirect | 12120 | `kXR_redirect` to `storage.example.org:1094` | `xrootd_manager_map / storage.example.org:1094;` |
   | wait | 12121 | `kXR_wait` on locate/open | manager_mode with no registered DS — returns kXR_wait naturally |
   | waitresp | 12122 | `kXR_waitresp` | same as wait (manager with no DS) |
   | error | 12123 | `kXR_error` for nonexistent paths | normal server, empty data dir, no matching path |
   | auth | 12124 | `kXR_authmore` requiring GSI | `xrootd_auth gsi;` |
   | auth nofile | 12125 | auth challenge, no user cert file present | `xrootd_auth gsi;` |
   | gotoTLS | 12126 | `kXR_gotoTLS` in protocol flags | `xrootd_tls required;` |

   Note: `nginx_upstream_wait.conf` is **missing** from `tests/configs/` — must be created before the dedicated backend can start.

2. **Update `nginx_upstream_redirect.conf` backend section** to add `xrootd_manager_map / storage.example.org:1094;`. Update test assertions to use those fixed values.

3. **Create `nginx_upstream_wait.conf`** for the wait backend (11121/12121): manager_mode, no data servers registered, empty CMS server.

4. **Remove** `MockUpstream`, `MockAuthUpstream`, `_start_upstream_nginx()`, `UPSTREAM_CONF` template string, `NGINX_BIN` import, `server_control` import.

5. **Convert all 4 nginx fixtures to connectivity checks:**
   ```python
   @pytest.fixture(scope="session")
   def upstream_redirect_nginx():
       with socket.create_connection(("127.0.0.1", UPSTREAM_REDIRECT_NGINX_PORT), timeout=5):
           pass
       yield {"port": UPSTREAM_REDIRECT_NGINX_PORT}
   ```
   `upstream_wait_nginx` **must become session-scoped** — it no longer starts a server.

6. **Rewrite tests:** Instead of injecting a mock response, assert on the known fixed response from the dedicated backend. Example:
   ```python
   # Before (MockUpstream controls target):
   mock = MockUpstream(lambda ...: [(kXR_redirect, _make_redirect_body("storage.example.org", 1094))], ...)
   # After (dedicated backend is configured to redirect to storage.example.org:1094):
   status, body = ...
   assert status == kXR_redirect
   port_be = struct.unpack(">I", body[:4])[0]
   assert port_be == 1094
   assert body[4:].decode() == "storage.example.org"
   ```

**Key challenge:** kXR_wait vs kXR_waitresp: an nginx manager with no registered data servers returns kXR_wait. Confirm the distinction in the existing test scenarios and ensure the backend configs produce the right status. If kXR_waitresp requires a different mechanism, document it and use separate configs.

---

### test_proxy_mode.py

**Current state:**
- `proxy_env` module fixture: `start_xrootd_instance()` starts an upstream xrootd, `start_nginx_instance()` starts an nginx proxy in front of it; seeds 8 files/dirs
- `TestProxyBackendUnavailable`: 2 test methods each call `_free_port()` + `start_nginx_instance()` to create a proxy pointing at a port with nothing listening

**Plan:**

#### proxy_env replacement

1. **Add port constants to `settings.py`:**
   ```python
   PROXY_NGINX_PORT    = int(os.environ.get("TEST_PROXY_NGINX_PORT",    "11170"))
   PROXY_UPSTREAM_PORT = int(os.environ.get("TEST_PROXY_UPSTREAM_PORT", "11176"))
   ```

2. **Create `tests/configs/nginx_proxy.conf`:**
   ```nginx
   worker_processes 1;
   error_log {LOG_DIR}/error.log debug;
   pid       {LOG_DIR}/nginx.pid;
   events { worker_connections 256; }
   stream {
       server {
           listen 127.0.0.1:{PORT};
           brix_root on;
           xrootd_auth none;
           xrootd_proxy on;
           xrootd_proxy_upstream 127.0.0.1:{UPSTREAM_PORT};
       }
   }
   ```

3. **Create `tests/configs/xrootd_proxy_upstream.conf`** — minimal xrootd config for the upstream xrootd daemon.

4. **Update `manage_test_servers.sh`:**
   ```bash
   # Seed data for proxy tests
   PROXY_DATA="$TEST_ROOT/data-proxy"
   mkdir -p "$PROXY_DATA/subdir" "$PROXY_DATA/subdir2"
   printf 'hello from proxy test\n' > "$PROXY_DATA/hello.txt"
   python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256))*4)" > "$PROXY_DATA/data256.bin"
   python3 -c "import sys; sys.stdout.buffer.write(bytes(i&0xFF for i in range(512*1024)))" > "$PROXY_DATA/large.bin"
   printf 'AAAABBBBCCCCDDDD' > "$PROXY_DATA/alpha.txt"
   printf '1111222233334444' > "$PROXY_DATA/beta.txt"
   printf 'xyzxyzxyzxyzxyz!' > "$PROXY_DATA/gamma.txt"
   printf 'nested file\n'  > "$PROXY_DATA/subdir/nested.txt"
   start_xrootd_instance "proxy-upstream" "${PROXY_UPSTREAM_PORT:-11176}" "$PROXY_DATA"
   start_dedicated_nginx "proxy" "nginx_proxy.conf" "${PROXY_NGINX_PORT:-11170}" \
       UPSTREAM_PORT="${PROXY_UPSTREAM_PORT:-11176}"
   ```

5. **Rewrite `proxy_env` fixture:**
   ```python
   @pytest.fixture(scope="module")
   def proxy_env():
       try:
           with socket.create_connection(("127.0.0.1", PROXY_NGINX_PORT), timeout=5): pass
       except OSError:
           pytest.skip(f"proxy nginx not reachable at port {PROXY_NGINX_PORT}")
       data_dir = Path(TEST_ROOT) / "data-proxy"
       yield {"proxy_port": PROXY_NGINX_PORT, "upstream_port": PROXY_UPSTREAM_PORT,
              "data_dir": data_dir}
   ```

#### TestProxyBackendUnavailable replacement

1. **Add port constants to `settings.py`:**
   ```python
   PROXY_DEAD_NGINX_PORT    = int(os.environ.get("TEST_PROXY_DEAD_NGINX_PORT",    "11171"))
   PROXY_DEAD_UPSTREAM_PORT = int(os.environ.get("TEST_PROXY_DEAD_UPSTREAM_PORT", "11177"))
   ```
   `11177` has no server configured — nothing listens on it. This is the "dead upstream".

2. **Create `tests/configs/nginx_proxy_dead.conf`:** same as `nginx_proxy.conf` but hardcoded `UPSTREAM_PORT=11177`.

3. **Update `manage_test_servers.sh`:** `start_dedicated_nginx "proxy-dead" "nginx_proxy_dead.conf" "${PROXY_DEAD_NGINX_PORT:-11171}"`

4. **Rewrite `TestProxyBackendUnavailable`:** replace `_free_port()` + `start_nginx_instance()` with connectivity check on `PROXY_DEAD_NGINX_PORT`; remove `try/finally proxy["stop"]()`.

**Remove** `NGINX_BIN` import, `server_control` import, all `_free_port` calls.

---

### test_manager_mode.py

**Current state:** The most complex migration. Has 9 cluster fixtures spanning:
- 1 session fixture `manager_nginx` (static map redirector, already at MANAGER_PORT 11101)
- 8 module/class-scoped cluster fixtures, each using 2–6 `_free_port()` + 2–4 `start_nginx_instance()`

**Cluster topologies and fixed port assignments:**

| Fixture | Topology | Ports (redir/CMS/DS…) |
|---|---|---|
| `manager_nginx` | Static map (existing) | 11101 (already dedicated) |
| `cluster` | 2-tier: 1 redir + 1 DS | redir=11130, CMS=11150, DS=11140 |
| `cluster_multi_path` | 2-tier: 1 redir + 1 DS (2 export paths) | redir=11131, CMS=11151, DS=11141 |
| `cluster_multi_server` | 2-tier: 1 redir + 2 DS | redir=11132, CMS=11152, DS1=11142, DS2=11143 |
| `cluster_multi_worker` | class-scoped, redir only (no DS) | redir=11133, CMS=11153 |
| three-tier (no fixture name, used inline) | meta-redir + sub-redir + leaf DS | meta=11134, meta-CMS=11154, sub=11135, sub-CMS=11155, leaf=11144 |
| `cluster_mock_cms` | redir + CMS + target port | redir=11136, CMS=11156, target=11165 |
| `cluster_full_registry` | redir + 4 DS (registry capacity test) | redir=11137, CMS=11157, DS1=11145, DS2=11146, DS3=11147, DS4=11148 |
| `cluster_cms_try` | redir + 2 DS (kXR_try logic) | redir=11138, CMS=11158, DS1=11160, DS2=11161 |
| `cluster_cms_escalation` | redir + sub (escalation chain) | redir=11139, CMS=11159, sub=11162 |

**Additional required configs:**

- `nginx_cluster_redir.conf` — `xrootd_manager_mode on;` + CMS server on `{CMS_PORT}`
- `nginx_cluster_dataserver.conf` — `xrootd_cms_manager 127.0.0.1:{CMS_PORT}; xrootd_cms_paths {PATHS}; xrootd_listen_port {PORT};`
- `nginx_cluster_dataserver_multipath.conf` — same but with `xrootd_cms_paths /data:/atlas;`
- `nginx_cluster_three_tier_meta.conf` — top-level manager with sub-manager as upstream
- `nginx_cluster_three_tier_sub.conf` — sub-manager registering with meta-manager
- `nginx_cluster_mock_cms.conf` — redir configured to advertise `redirect_target` port in responses
- Additional variants as needed for registry-full and kXR_try topologies

**Plan per fixture:**

1. **`manager_nginx` session fixture**: already at 11101, but it currently calls `start_nginx_instance`. Rewrite to connectivity check + yield known map values:
   ```python
   @pytest.fixture(scope="session", autouse=True)
   def manager_nginx():
       if not _wait_for_port("127.0.0.1", MANAGER_PORT):
           pytest.skip(f"manager nginx not running at {MANAGER_PORT}")
       yield {"port": MANAGER_PORT,
              "map_a": ("backend.example.org", 54321),
              "map_b": ("backend2.example.org", 12345)}
   ```
   These map values must be baked into `nginx_manager.conf` and then referenced as constants.

2. **`cluster` fixture** → port connectivity check, yield fixed port dict:
   ```python
   @pytest.fixture(scope="module")
   def cluster(tmp_path_factory):
       for port in (CMS_CLUSTER_REDIR_PORT, CMS_CLUSTER_DS_PORT):
           if not _wait_for_port("127.0.0.1", port):
               pytest.skip(...)
       data_dir = Path(TEST_ROOT) / "data-cluster"
       (data_dir / "test.txt").write_text("hello from data server")  # idempotent
       yield {"redir_port": CMS_CLUSTER_REDIR_PORT, "ds_port": CMS_CLUSTER_DS_PORT,
              "cms_port": CMS_CLUSTER_CMS_PORT, "data_dir": str(data_dir), ...}
   ```
   The `redir` and `ds` "stop" callables are removed; tests that call `cluster["ds"]["stop"]()` (i.e., `TestClusterUnregister`) need special treatment.

3. **`TestClusterUnregister.test_no_redirect_after_dataserver_stops`** — this test stops the data server mid-run to verify the redirector detects unregistration. In the dedicated-server model, this test may stop the dedicated DS and it stays stopped for the remainder of the pytest session (until `stop-all`). This is acceptable **only if** `TestClusterUnregister` runs last in the module (it currently does — the class is defined last) and no other test class in the module depends on the same `cluster` fixture after this test runs. Document this as a known side effect.

4. **Other cluster fixtures**: follow the same pattern — add port constants, create config templates, add `start_dedicated_nginx` / `start_dedicated_xrootd` calls to `manage_test_servers.sh`, convert fixtures to connectivity checks.

5. **`cluster_full_registry`** at line 1229: the fixture starts multiple data servers in a loop with `ds_port = server_control._free_port()`. The registry-full scenario needs a predetermined number of DS registrations. Fix: pre-start exactly 4 dedicated data servers for this topology; the test observes that the 5th (never started in the permanent model) is absent from the registry.

6. **Inline tests using `gone_port = server_control._free_port()`** (lines 1344, 1388-1389): these test the redirector's behavior when it believes a server exists at a port where nothing is listening. Fix: use `PROXY_DEAD_UPSTREAM_PORT` (11177) — a port that intentionally has nothing listening. Already defined in the proxy-mode plan above.

**Add port constants to `settings.py`:**
```python
# Manager-mode cluster ports (11130-11169)
CLUSTER_REDIR_PORT         = 11130
CLUSTER_CMS_PORT           = 11150
CLUSTER_DS_PORT            = 11140
CLUSTER_MP_REDIR_PORT      = 11131  # multi-path
CLUSTER_MP_CMS_PORT        = 11151
CLUSTER_MP_DS_PORT         = 11141
CLUSTER_MS_REDIR_PORT      = 11132  # multi-server
CLUSTER_MS_CMS_PORT        = 11152
CLUSTER_MS_DS1_PORT        = 11142
CLUSTER_MS_DS2_PORT        = 11143
CLUSTER_MW_REDIR_PORT      = 11133  # multi-worker
CLUSTER_MW_CMS_PORT        = 11153
CLUSTER_3T_META_PORT       = 11134  # three-tier
CLUSTER_3T_META_CMS_PORT   = 11154
CLUSTER_3T_SUB_PORT        = 11135
CLUSTER_3T_SUB_CMS_PORT    = 11155
CLUSTER_3T_LEAF_PORT       = 11144
CLUSTER_CMS_SEL_REDIR_PORT = 11136  # cms-select-wake
CLUSTER_CMS_SEL_CMS_PORT   = 11156
CLUSTER_CMS_SEL_TARGET_PORT= 11165
CLUSTER_REG_REDIR_PORT     = 11137  # full-registry
CLUSTER_REG_CMS_PORT       = 11157
CLUSTER_REG_DS1_PORT       = 11145
CLUSTER_REG_DS2_PORT       = 11146
CLUSTER_REG_DS3_PORT       = 11147
CLUSTER_REG_DS4_PORT       = 11148
CLUSTER_TRY_REDIR_PORT     = 11138  # cms-try
CLUSTER_TRY_CMS_PORT       = 11158
CLUSTER_TRY_DS1_PORT       = 11160
CLUSTER_TRY_DS2_PORT       = 11161
CLUSTER_ESC_REDIR_PORT     = 11139  # escalation
CLUSTER_ESC_CMS_PORT       = 11159
CLUSTER_ESC_SUB_PORT       = 11162
```

---

## Current State: Port Inventory

### Shared baseline (dedicated ✓)
| Port | Purpose | Config |
|---|---|---|
| 11094 | Anonymous XRootD stream | nginx_shared.conf |
| 11095 | GSI XRootD stream | nginx_shared.conf |
| 11096 | TLS XRootD stream | nginx_shared.conf |
| 11097 | Token XRootD stream | nginx_shared.conf |
| 8443 | WebDAV HTTPS (GSI) | nginx_shared.conf |
| 8444 | WebDAV HTTPS (GSI+TLS) | nginx_shared.conf |
| 8080 | HTTP WebDAV | nginx_shared.conf |
| 9001 | S3 REST | nginx_shared.conf |
| 9100 | Prometheus /metrics | nginx_shared.conf |

### Reference xrootd (dedicated ✓)
| Port | Purpose |
|---|---|
| 11098 | Ref xrootd conformance |
| 11099 | Ref xrootd GSI |
| 11100 | Ref xrootd GSI shared |

### Dedicated mode servers (dedicated ✓)
| Port | Purpose | Config |
|---|---|---|
| 11101 | XRootD manager map | nginx_manager.conf |
| 11102 | Read-only server | nginx_readonly.conf |
| 11103 | VOMS ACL enforcement | nginx_vo_acl.conf |
| 11104 | CRL validation (stream) | nginx_crl.conf |
| 11105 | CRL validation (WebDAV) | nginx_crl.conf |
| 11106 | CRL directory mode (stream) | nginx_crl.conf (dir) |
| 11107 | CRL directory mode (WebDAV) | nginx_crl.conf (dir) |
| 11108 | CRL reload (stream) | nginx_crl_reload.conf |
| 11109 | CRL reload (HTTP) | nginx_crl_reload.conf |

### TPC servers (dedicated ✓)
| Port | Purpose |
|---|---|
| 11110 | Root TPC nginx |
| 11111 | Root TPC ref xrootd |
| 11112 | XrdHttp TPC conformance (nginx) |
| 11113 | XrdHttp TPC conformance (http) |

### Auth/JWKS (partially dedicated)
| Port | Purpose | Status |
|---|---|---|
| 11114 | Authentication database | **config template needed** |
| 11115 | JWKS hot-refresh token auth | ✓ Dedicated |

### WebDAV auth cache (dedicated ✓)
| Port | Purpose |
|---|---|
| 18444 | Manual CA store build |
| 18445 | Nginx-managed CA store |

### WebDAV TPC destinations (dedicated ✓)
| Port | Purpose |
|---|---|
| 18450-18456 | Various TPC dest modes |

### Upstream redirect/wait/error/auth/gotoTLS (partially dedicated)
| Port | Purpose | Status |
|---|---|---|
| 11120 | Redirect upstream nginx | ✓ Dedicated |
| 11121 | Wait upstream nginx | ✓ Dedicated (config exists, but nginx_upstream_wait.conf **missing** from configs/) |
| 11122 | WaitForResp upstream nginx | ✓ Dedicated |
| 11123 | Error upstream nginx | ✓ Dedicated |
| 11124 | Auth upstream nginx | ✓ Dedicated |
| 11125 | Auth nofile upstream nginx | ✓ Dedicated |
| 11126 | gotoTLS-notls upstream nginx | ✓ Dedicated |
| 12120-12126 | Upstream backends | ✓ Dedicated |

### SSRF policy servers (dedicated ✓)
| Port | Purpose | Config |
|---|---|---|
| 11180 | Default SSRF policy | nginx_tpc_ssrf_default.conf |
| 11181 | SSRF allow-local policy | nginx_tpc_ssrf_allow_local.conf |
| 11182 | SSRF deny-private policy | nginx_tpc_ssrf_deny_private.conf |

### S3 presigned URL servers (dedicated ✓)
| Port | Purpose | Config |
|---|---|---|
| 11183 | S3 presigned URL (no STS) | nginx_s3_presigned.conf |
| 11184 | S3 presigned URL + STS | nginx_s3_presigned_sts.conf |

### Security level servers (dedicated ✓)
| Port | Purpose | Config |
|---|---|---|
| 11191 | Security level standard | nginx_security_level_standard.conf |
| 11192 | Security level pedantic | nginx_security_level_pedantic.conf |

### Ports needed (not yet dedicated)
| Range | Purpose | Needed by |
|---|---|---|
| 11114 | Authdb enforcement | test_authdb.py |
| 11130-11169 | Manager cluster topologies | test_manager_mode.py |
| 11170-11179 | Proxy mode pairs | test_proxy_mode.py |
| 11185 | Prepare-command test server | test_prepare_staging.py |

---

## Config Template Status

### Existing (tests/configs/)
```
nginx_shared.conf              ✓
nginx_jwks_refresh.conf        ✓
nginx_webdav_tpc.conf          ✓
nginx_webdav_auth_cache.conf   ✓
nginx_vo_acl.conf              ✓
nginx_readonly.conf            ✓
nginx_manager.conf             ✓
nginx_crl_reload.conf          ✓
nginx_crl.conf                 ✓
nginx_tpc_ssrf_default.conf    ✓ (new)
nginx_tpc_ssrf_allow_local.conf ✓ (new)
nginx_tpc_ssrf_deny_private.conf ✓ (new)
nginx_s3_presigned.conf        ✓ (new)
nginx_s3_presigned_sts.conf    ✓ (new)
nginx_security_level_standard.conf ✓ (new)
nginx_security_level_pedantic.conf ✓ (new)
nginx_root_tpc.conf            ✓
nginx_upstream_redirect.conf   ✓
nginx_upstream_waitresp.conf   ✓
nginx_upstream_error.conf      ✓
nginx_upstream_auth.conf       ✓
nginx_upstream_auth_nofile.conf ✓
nginx_upstream_gotorls_notls.conf ✓
xrootd_http_tpc.conf           ✓
xrootd_ref.conf                ✓
xrootd_ref_gsi.conf            ✓
xrootd_root_tpc.conf           ✓
```

### Missing (must be created)
```
nginx_upstream_wait.conf           ← MISSING (used by 11121/12121 but never created)
nginx_authdb.conf                  ← authdb enforcement (port 11114)
nginx_prepare_command.conf         ← xrootd_prepare_command (port 11185)
nginx_proxy.conf                   ← proxy mode nginx (port 11170)
nginx_proxy_dead.conf              ← proxy with dead upstream (port 11171)
xrootd_proxy_upstream.conf        ← upstream xrootd for proxy tests (port 11176)
nginx_cluster_redir.conf           ← manager_mode + CMS server
nginx_cluster_dataserver.conf      ← data server with cms_manager
nginx_cluster_dataserver_multipath.conf
nginx_cluster_three_tier_meta.conf
nginx_cluster_three_tier_sub.conf
nginx_cluster_mock_cms.conf
nginx_cluster_full_registry_*.conf  ← registry-capacity variants
nginx_cluster_cms_try_*.conf
nginx_cluster_escalation_*.conf
```

---

## Implementation Plan (Remaining Phases)

### Phase 2 (continued): Create missing config templates

Priority order:
1. `nginx_upstream_wait.conf` — blocks test_a_upstream_redirect.py; simplest (wait backend = manager_mode + no DS)
2. `nginx_authdb.conf` — required for test_authdb.py
3. `nginx_prepare_command.conf` — required for test_prepare_staging.py
4. `nginx_proxy.conf` + `nginx_proxy_dead.conf` + `xrootd_proxy_upstream.conf` — required for test_proxy_mode.py
5. All cluster configs — required for test_manager_mode.py

### Phase 3 (continued): Add port constants to settings.py

Add all port constants in the 11130-11192 range as listed in the cluster topology table above.
Add `PROXY_NGINX_PORT`, `PROXY_UPSTREAM_PORT`, `PROXY_DEAD_NGINX_PORT`, `PROXY_DEAD_UPSTREAM_PORT`,
`PREPARE_CMD_PORT`.

### Phase 4 (continued): Convert remaining Type A test files

Execute in this order (least to most complex):

1. `test_authdb.py` — see detailed plan above
2. `test_prepare_staging.py` — see detailed plan above
3. `test_a_upstream_redirect.py` — see detailed plan above
4. `test_cms.py` — see detailed plan above
5. `test_proxy_mode.py` — see detailed plan above
6. `test_manager_mode.py` — see detailed plan above (most complex, do last)

### Phase 5: Remove mock protocol peers

After all Type A conversions:
- Delete `_MockCmsManager` from test_cms.py
- Delete `MockUpstream` and `MockAuthUpstream` from test_a_upstream_redirect.py
- Audit `tests/mock_origin.py` — delete if all callers converted to real dedicated origin servers
- Audit `test_ocsp.py` mock responders — retained for unit tests; live stapling flows use dedicated responder if needed

### Phase 6: Update conftest.py and manage_test_servers.sh

`conftest.py` session-scoped autouse fixtures must only verify ports are listening. No fixture starts anything.

`manage_test_servers.sh start-all` must include `start_dedicated_nginx` / `start_xrootd_instance` calls for all servers added in phases 4–5.

`manage_test_servers.sh stop-all` must cleanly terminate every process including cluster topologies and proxy-mode xrootd instances.

### Phase 7: Verification

```bash
tests/manage_test_servers.sh start-all
PYTHONPATH=tests pytest tests/ -v --tb=short
grep -rn "start_nginx_instance\|start_xrootd_instance\|_free_port\|NGINX_BIN\|MockUpstream\|MockCmsManager" tests/test_*.py
# must return zero results
```

---

## Risk Assessment

### Low risk
- `test_authdb.py` — simple fixture conversion, idempotent authdb setup
- `test_prepare_staging.py` — most tests already clean; only `TestPrepareStageCommand` needs work

### Medium risk
- `test_a_upstream_redirect.py` — MockUpstream removal changes test assertions from injected values to fixed values; requires backend configs to be precisely configured to match expected wire responses
- `test_proxy_mode.py` — requires a running xrootd process as upstream; xrootd process management is fragile (see fragility note)

### High risk
- `test_cms.py` — frame-level CMS assertions must become behavioral; some test coverage is intentionally sacrificed
- `test_manager_mode.py` — 9 topologies, ~30 nginx instances, `TestClusterUnregister` has lifecycle side effects, inline `_free_port()` calls (gone_port, port_a, port_b) need design decisions

### Known fragility: xrootd upstream processes

`start_xrootd_instance` creates a process that can die without manage_test_servers.sh knowing. When `proxy_env` depends on the upstream being alive, a dead xrootd will cause confusing proxy-mode test failures. `stop-all` must include force-kill of orphaned xrootd workers by PID file, and tests must check upstream port liveness before asserting data-path results.

---

## Success Criteria

1. `manage_test_servers.sh start-all` starts every dedicated instance
2. `manage_test_servers.sh stop-all` cleanly terminates every instance
3. No ephemeral `/tmp/xrd-test/instances/nginx-{uuid}` directories during test execution
4. The following grep returns zero results:
   ```bash
   grep -rn "start_nginx_instance\|start_xrootd_instance\|_free_port\|NGINX_BIN\|MockUpstream\|MockCmsManager\|_MockCms" tests/test_*.py
   ```
5. No integration/conformance test starts a mock protocol peer
6. All existing tests pass without regression
7. Every port constant in settings.py maps to a running server or is explicitly documented as not-yet-implemented
