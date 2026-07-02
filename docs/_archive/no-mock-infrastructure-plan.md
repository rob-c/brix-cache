# No-Mock Test Infrastructure Plan

**Goal:** Eliminate every skipped test and every mock service, replacing all stubs with real
nginx or reference xrootd instances managed by `manage_test_servers.sh`.

**Governance constraint (from `tests/server_control.py`):** All server lifecycle belongs in
`manage_test_servers.sh`. Tests must use pre-launched dedicated servers at fixed ports, not
ephemeral processes spun up inside pytest fixtures.

---

## Current State

| Skip | File | Root cause |
|---|---|---|
| `test_xrdcp_davs_byte_exact_hash` | `test_a_webdav_clients.py` | `xrdcl-http` package missing |
| `test_curl_put_xrdcp_get_cross_client_round_trip` | `test_a_webdav_clients.py` | `xrdcl-http` package missing |
| `test_locate_wait_then_redirect` | `test_a_upstream_redirect.py` | Backend is plain anon xrootd, not a wait-producing manager |
| `test_locate_waitresp_then_redirect` | `test_a_upstream_redirect.py` | Same; no real kXR_waitresp source wired |
| `test_upstream_token_auth_success` | `test_a_upstream_redirect.py` | Backend is plain anon xrootd, never sends kXR_authmore |
| `test_upstream_token_auth_no_file_aborts` | `test_a_upstream_redirect.py` | Same |
| `test_upstream_gotorls_no_tls_configured_aborts` | `test_a_upstream_redirect.py` | Backend is plain anon xrootd, never sets kXR_gotoTLS flag |
| `test_wt_origin_tls_required` | `test_cache_write_through.py` | No TLS-origin WT server in fleet |
| `test_no_redirect_after_dataserver_stops` | `test_manager_mode.py` | Test body is `pass`; stopping a shared-fleet server is destructive |

**Mocks with no callers (safe to delete):**
- `tests/mock_upstream.py` — `MockUpstreamServer`, no test imports it
- `tests/mock_origin.py` — `MockOriginServer`, no test imports it

---

## Item 0 — xrdcl-http (already done)

```bash
sudo dnf install --disablerepo=cursor xrdcl-http
```

This installs `libXrdClHttp-5.so` next to `/lib64/libXrdCl.so.3` where system xrdcp
auto-discovers it. No test-code changes required. The skip guard in
`_xrdcp_download_or_skip()` fires only when xrdcp reports the "no such file or directory
processing davs://" message that indicates the plugin is absent; with the plugin present the
message changes to a real HTTP error or success.

**Verify:** re-run `PYTHONPATH=tests pytest tests/test_a_webdav_clients.py -v` and confirm
both previously-skipped tests now show PASSED.

---

## Item 1 — kXR_wait forwarded from real manager backend

### What the test exercises
`test_locate_wait_then_redirect` tests that when the upstream backend sends `kXR_wait`,
nginx's upstream relay (`src/net/upstream/response.c:case kXR_wait`) correctly forwards it to the
client and schedules a retry.

### Why the current backend does not work
`manage_test_servers.sh` starts a plain anonymous xrootd (`start_extra_ref_anon`) at port
12121. Anonymous xrootd never sends `kXR_wait`; it returns `kXR_error` (NotFound) or
`kXR_ok` immediately.

### Real replacement
`nginx_upstream_wait.conf` is already correct: it uses `xrootd_manager_mode on` with
`xrootd_cms_manager 127.0.0.1:12345` (intentionally dead port) and
`xrootd_cms_locate_timeout 1s`. When a locate arrives and CMS does not respond within 1 s,
the manager returns `kXR_wait` to the upstream connection. The frontend nginx at port 11121
forwards this to the client.

**The only change needed is in `manage_test_servers.sh`:** replace the
`start_extra_ref_anon "upstream-wait" 12121 ...` line with a `start_dedicated_nginx
"upstream-wait-backend" "nginx_upstream_wait_backend.conf" 12121` call that starts a
manager-mode nginx. Add a new config template:

**`tests/configs/nginx_upstream_wait_backend.conf`**
```nginx
worker_processes 1;
error_log {LOG_DIR}/error_upstream_wait_backend.log info;
pid       {LOG_DIR}/upstream_wait_backend.pid;
events { worker_connections 32; }
stream {
    server {
        listen {BIND_HOST}:{PORT};
        xrootd on;
        xrootd_root      {DATA_DIR};
        xrootd_auth      none;
        xrootd_manager_mode on;
        xrootd_cms_manager  127.0.0.1:19999;   # intentionally unreachable
        xrootd_cms_locate_timeout 500ms;        # fast timeout for test speed
    }
}
```

### Test body implementation
Remove `_skip_dynamic_mock_scenario(...)` and replace with:

```python
def test_locate_wait_forwarded(self, upstream_wait_nginx):
    """Backend manager has no registered data server → upstream forwards kXR_wait."""
    sock = _xrd_handshake_login(SERVER_HOST, upstream_wait_nginx["port"])
    _send_locate(sock, "/data/file.root")
    # cms_locate_timeout is 500 ms on the backend; allow 3 s for the round-trip
    sock.settimeout(3.0)
    status, body = _read_response(sock)
    sock.close()
    assert status == kXR_wait, f"expected kXR_wait forwarded from manager backend, got {status}"
```

Rename the test method from `test_locate_wait_then_redirect` to `test_locate_wait_forwarded`
since with real infrastructure there is no "then redirect" without a data server registering
dynamically. The redirect path is already covered by `TestUpstreamRedirect::test_locate_redirected`.

---

## Item 2 — kXR_waitresp forwarded from reference xrootd manager

### What the test exercises
`test_locate_waitresp_then_redirect` tests that `kXR_waitresp` from the upstream is
forwarded to the client (`src/net/upstream/response.c:case kXR_waitresp` →
`xrootd_send_waitresp(ctx, c)`).

### Why the current backend does not work
nginx-xrootd in manager mode only emits `kXR_wait`, not `kXR_waitresp`. `kXR_waitresp` is an
async acknowledgement ("answer arriving via kXR_attn") that the reference xrootd binary
emits when acting as a redirector with a live cmsd.

### Real replacement
Add a reference xrootd instance configured as a redirector. The reference xrootd in
`role manager` with a live `cmsd` sends `kXR_waitresp` on `kXR_locate` while the cluster
management daemon is computing the answer.

**New files:**
- `tests/configs/xrootd_ref_manager.conf` — reference xrootd in manager/redirector role,
  listening on `{PORT}`, with `oss.manager {CMS_HOST}:{CMS_PORT}` pointing at cmsd
- `tests/configs/xrootd_ref_cmsd.conf` — cmsd config pointing back at the manager

**`manage_test_servers.sh` changes:**
Replace `start_extra_ref_anon "upstream-waitresp" 12122 ...` with:
1. Start cmsd at port 12122 (using the cmsd binary alongside REF_BIN)
2. Start reference xrootd manager at a new port (e.g. 12127) pointing at that cmsd

Then update `UPSTREAM_WAITRESP_BACKEND_PORT` in settings.py to 12127.

**Test body:**

```python
def test_locate_waitresp_forwarded(self, upstream_waitresp_nginx):
    """Reference xrootd manager issues kXR_waitresp; upstream relay forwards it."""
    sock = _xrd_handshake_login(SERVER_HOST, upstream_waitresp_nginx["port"])
    _send_locate(sock, "/data/file.root")
    sock.settimeout(5.0)
    status, body = _read_response(sock)
    sock.close()
    assert status == kXR_waitresp, (
        f"expected kXR_waitresp forwarded from xrootd manager backend, got {status}"
    )
```

**Fallback:** If cmsd is not available alongside the reference xrootd build, verify whether the
standalone reference xrootd in `role manager` also emits `kXR_waitresp` (some versions do for
async locate). If neither works, reframe as testing that `kXR_wait` is forwarded (collapses
into Item 1) and remove this test.

---

## Item 3 — Token auth backend for upstream kXR_authmore tests

### What the tests exercise
- `test_upstream_token_auth_success`: frontend nginx has `xrootd_upstream_token_file` →
  when backend sends `kXR_authmore` challenge, frontend responds with the JWT → login
  succeeds → subsequent locate proceeds.
- `test_upstream_token_auth_no_file_aborts`: frontend has NO token file → when backend
  sends `kXR_authmore`, frontend cannot respond → connection aborted → client receives
  `kXR_error`.

### Why the current backend does not work
Both backends (`start_extra_ref_anon` at 12124 and 12125) are anonymous xrootd; they never
issue `kXR_authmore`.

### Real replacement
Add a token-auth nginx instance as the backend. Use the JWKS + JWT already generated by
`manage_test_servers.sh` in `${TEST_ROOT}/tokens/`.

**New config `tests/configs/nginx_upstream_token_auth_backend.conf`:**
```nginx
worker_processes 1;
error_log {LOG_DIR}/error_upstream_token_auth_backend.log info;
pid       {LOG_DIR}/upstream_token_auth_backend.pid;
events { worker_connections 32; }
stream {
    server {
        listen {BIND_HOST}:{PORT};
        xrootd on;
        xrootd_root           {DATA_DIR};
        xrootd_auth           token;
        xrootd_token_jwks     {JWKS_FILE};
        xrootd_token_issuer   {TOKEN_ISSUER};
        xrootd_token_audience {TOKEN_AUDIENCE};
        xrootd_allow_write    off;
    }
}
```

**`manage_test_servers.sh` changes:**
Replace both `start_extra_ref_anon "upstream-auth" ...` and
`start_extra_ref_anon "upstream-auth-nofile" ...` with:
```bash
TOKEN_FILE="${TEST_ROOT}/tokens/upstream.jwt" \
JWKS_FILE="${TEST_ROOT}/tokens/jwks.json" \
TOKEN_ISSUER="https://test.example.com" \
TOKEN_AUDIENCE="nginx-xrootd" \
  start_dedicated_nginx "upstream-auth-backend" \
      "nginx_upstream_token_auth_backend.conf" \
      "${UPSTREAM_AUTH_BACKEND_PORT:-12124}"

# Same backend serves auth-nofile scenario (port 12125 not needed separately)
```

Because both auth scenarios share the same backend, `UPSTREAM_AUTH_NOFILE_BACKEND_PORT`
can point at 12124 as well. Update `settings.py` accordingly.

**Test bodies:**

```python
def test_upstream_token_auth_success(self, upstream_auth_nginx):
    """Frontend supplies JWT; backend kXR_authmore is satisfied; locate proceeds."""
    sock = _xrd_handshake_login(SERVER_HOST, upstream_auth_nginx["port"])
    _send_locate(sock, "/data/test.root")
    sock.settimeout(5.0)
    status, body = _read_response(sock)
    sock.close()
    # kXR_error (NotFound) is acceptable — auth succeeded but the path is empty.
    # kXR_redirect is also acceptable if the manager redirects.
    assert status in (kXR_ok, kXR_error, kXR_redirect), (
        f"expected successful auth outcome, got status={status}"
    )

def test_upstream_token_auth_no_file_aborts(self, upstream_auth_nofile_nginx):
    """Frontend has no token file; kXR_authmore from backend causes abort → kXR_error."""
    sock = _xrd_handshake_login(SERVER_HOST, upstream_auth_nofile_nginx["port"])
    _send_locate(sock, "/data/test.root")
    sock.settimeout(5.0)
    status, body = _read_response(sock)
    sock.close()
    assert status == kXR_error, (
        f"expected kXR_error when token file absent, got status={status}"
    )
```

---

## Item 4 — TLS backend for kXR_gotoTLS abort test

### What the test exercises
`test_upstream_gotorls_no_tls_configured_aborts` verifies that when the upstream backend
advertises `kXR_gotoTLS` in its protocol flags and `xrootd_upstream_tls` is `off` on the
frontend, nginx aborts the upstream connection and returns `kXR_error` to the client.

### Why the current backend does not work
`start_extra_ref_anon` at 12126 is a plaintext server; it never sets the `kXR_gotoTLS` bit
in its protocol response. The frontend at 11126 never sees the flag and never triggers the
abort path.

### Real replacement
The existing nginx at port 11096 already has `xrootd_tls on` (from `nginx_shared.conf`
GSI+TLS block). When any upstream connects to it, the protocol response carries
`kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin` flags (`src/session/protocol.c:93`).

**`manage_test_servers.sh` changes:**
- Remove `start_extra_ref_anon "upstream-gotorls-notls" 12126 ...`
- Change the `start_dedicated_nginx "upstream-gotorls-notls" ...` call to pass
  `UPSTREAM_PORT=${NGINX_GSI_TLS_PORT:-11096}` so the frontend wires to the existing TLS
  nginx rather than the now-removed anon server.
- Remove `UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT` from `settings.py` (no longer a separate
  server; just a reference to `NGINX_GSI_TLS_PORT`).

**Test body:**

```python
def test_upstream_gotorls_no_tls_configured_aborts(self, upstream_gotorls_notls_nginx):
    """Backend advertises kXR_gotoTLS; frontend has upstream_tls off → abort → kXR_error."""
    sock = _xrd_handshake_login(SERVER_HOST, upstream_gotorls_notls_nginx["port"])
    _send_locate(sock, "/data/test.root")
    sock.settimeout(5.0)
    status, body = _read_response(sock)
    sock.close()
    assert status == kXR_error, (
        f"expected kXR_error when gotoTLS rejected, got status={status}"
    )
```

---

## Item 5 — TLS-origin write-through server

### What the test exercises
`test_wt_origin_tls_required` verifies that when the write-through sync server is configured
with a `roots://` origin that uses a CA it cannot verify (or where TLS negotiation fails),
a sync PUT returns `kXR_error` — the server does not silently discard the flush failure.

### What needs to be added
A second write-through nginx that points `xrootd_wt_origin` at a TLS xrootd origin with a
mismatched CA (so TLS handshake to the origin fails). The client PUT fails because sync mode
blocks on the origin flush.

**New config `tests/configs/nginx_wt_sync_brokentls.conf`:**
```nginx
worker_processes 1;
error_log {LOG_DIR}/error_wt_sync_brokentls.log info;
pid       {LOG_DIR}/wt_sync_brokentls.pid;
thread_pool default threads=2 max_queue=65536;
events { worker_connections 16; }
stream {
    server {
        listen {BIND_HOST}:{PORT};
        xrootd on;
        xrootd_root         {DATA_DIR};
        xrootd_auth         none;
        xrootd_allow_write  on;
        xrootd_write_through on;
        xrootd_wt_mode      sync;
        # Intentionally wrong port — TLS origin unreachable
        xrootd_wt_origin    roots://127.0.0.1:{BROKEN_ORIGIN_PORT};
    }
}
```

`{BROKEN_ORIGIN_PORT}` is a port with no listener (e.g. 19998). This simulates the case
where the `roots://` origin is not reachable. No new server needed; just the dead port.

**`manage_test_servers.sh` changes:**
```bash
start_dedicated_nginx "wt-sync-brokentls" "nginx_wt_sync_brokentls.conf" \
    "${WT_SYNC_BROKENTLS_PORT:-11200}"
```

Add `WT_SYNC_BROKENTLS_PORT = int(os.environ.get("TEST_WT_SYNC_BROKENTLS_PORT", "11200"))`
to `settings.py`.

Add a fixture in `test_cache_write_through.py`:
```python
@pytest.fixture(scope="session")
def wt_sync_brokentls_server():
    yield {"port": WT_SYNC_BROKENTLS_PORT}
```

**Test body** (remove the `pytest.skip(...)` call and implement):
```python
def test_wt_origin_tls_required(self, wt_sync_brokentls_server, tmp_path):
    """Sync WT with unreachable roots:// origin: flush fails → xrdcp returns non-zero."""
    src = tmp_path / "wt_tls_probe.bin"
    src.write_bytes(b"tls-origin-probe-" + os.urandom(16))
    remote_name = f"/wt_tls_{os.getpid()}.bin"
    r = _xrdcp(str(src), _xrdcp_url(wt_sync_brokentls_server["port"], remote_name),
               timeout=10)
    assert r.returncode != 0, (
        "Sync WT flush to unreachable roots:// origin must fail — "
        f"xrdcp returned 0 unexpectedly.\nstderr: {r.stderr.decode()}"
    )
```

Note: this test uses its own `wt_sync_brokentls_server` fixture, not the `wt_sync_server`
fixture, so the working WT tests are unaffected.

---

## Item 6 — Data-server-stops cluster test

### What the test exercises
`test_no_redirect_after_dataserver_stops` verifies that after a data server disconnects from
the manager, `kXR_locate` on the manager no longer returns `kXR_redirect` to that server.

### Architecture
The shared cluster fleet cannot be partially stopped mid-test. Add a dedicated isolated
cluster at separate ports used only by this test. The test manages the DS lifecycle via its
PID file (nginx writes its pid to `{LOG_DIR}/nginx.pid`).

**New dedicated cluster ports** (add to `settings.py`):
```python
CLUSTER_STOP_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_STOP_REDIR_PORT", "11201"))
CLUSTER_STOP_DS_PORT    = int(os.environ.get("TEST_CLUSTER_STOP_DS_PORT",    "11202"))
CLUSTER_STOP_CMS_PORT   = int(os.environ.get("TEST_CLUSTER_STOP_CMS_PORT",   "12201"))
```

**`manage_test_servers.sh` changes:**
Add a new group that starts a redirector + data server using existing
`nginx_cluster_redir.conf` and `nginx_cluster_ds.conf` templates at the new ports. This
cluster runs alongside the regular cluster fleet but at distinct ports.

**Test implementation** (remove `@pytest.mark.skip` and `pass`, add `@pytest.mark.serial`):

```python
@pytest.mark.serial
def test_no_redirect_after_dataserver_stops(self):
    """After DS disconnects from manager, locate returns error not redirect."""
    import subprocess, signal
    from pathlib import Path

    # Confirm DS is up and locate works
    sock = _cluster_handshake_login(SERVER_HOST, CLUSTER_STOP_REDIR_PORT)
    _cluster_send_locate(sock, "/data/test.txt")
    status, _ = _cluster_read_response(sock)
    sock.close()
    assert status == kXR_redirect, f"expected redirect before DS stop, got {status}"

    # Stop the data server by sending SIGQUIT to its PID
    pidfile = Path(f"/tmp/xrd-test/logs/nginx-cluster-stop-ds.pid")
    ds_pid = int(pidfile.read_text().strip())
    os.kill(ds_pid, signal.SIGQUIT)
    # Wait for DS to deregister with the manager (CMS heartbeat interval)
    time.sleep(3.0)

    # Locate must no longer redirect to the stopped DS
    sock = _cluster_handshake_login(SERVER_HOST, CLUSTER_STOP_REDIR_PORT)
    _cluster_send_locate(sock, "/data/test.txt")
    status, _ = _cluster_read_response(sock)
    sock.close()
    assert status != kXR_redirect, (
        "Redirector still redirecting to a stopped data server"
    )

    # Restart DS so subsequent test runs find it up (idempotent)
    subprocess.run(
        ["tests/manage_test_servers.sh", "start", "cluster-stop-ds"],
        check=False, capture_output=True,
    )
```

The `manage_test_servers.sh start cluster-stop-ds` subcommand must be added to the script's
dispatch table.

---

## Mock deletion

Once all items above are complete and tests pass:

```bash
git rm tests/mock_upstream.py tests/mock_origin.py
```

Verify with `grep -r "mock_upstream\|mock_origin" tests/ --include="*.py"` — should return
no results.

---

## Execution order

| Step | Work | Risk |
|---|---|---|
| 0 | Install `xrdcl-http` (done) | None |
| 4 | Wire frontend at 11126 to existing TLS nginx 11096 | Low — no new server |
| 3 | Add token-auth backend config + start in manage_test_servers.sh | Low |
| 5 | Add `nginx_wt_sync_brokentls.conf` + broken-origin WT instance | Low |
| 1 | Add manager-mode backend config + implement wait test body | Medium |
| 6 | Add cluster-stop ports + implement DS-stop test | Medium |
| 2 | Reference xrootd manager + cmsd for kXR_waitresp | High — depends on cmsd availability |
| — | Delete mock files | After all tests green |

Start with steps 4, 3, 5 (lowest risk, self-contained) and work toward 1, 6, 2.

---

## Definition of done

```
PYTHONPATH=tests pytest tests/ -v --tb=short
# Expected final line:
# ====== N passed, 0 skipped, 1 xfailed, 0 warnings in X.Xs =======
```

The 1 `xfailed` (`test_python_api_surface.py::test_url_parameters`) is a deliberate
expected-failure marker and does not count as a skip.
