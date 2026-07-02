# Failing Tests — Investigation and Fix Guide

Status as of 2026-05-19: 7 confirmed failing tests across three functional areas,
plus a category of infrastructure-dependent tests that require a reference xrootd
HTTP daemon not started by `manage_test_servers.sh`.

The failing tests are documented here in the same format used by
`tier1-implementation-plan.md` so that each one can be picked up, investigated,
and fixed independently.

---

## 1. CMS session redirect returns kXR_ServerError

**Status:** Failing | **Effort:** Medium | **Impact:** High

### Tests

```
tests/test_manager_mode.py::TestCmsSelectWake::test_locate_wakes_on_cms_select
tests/test_manager_mode.py::TestCmsKyrTry::test_locate_redirects_to_first_try_entry
tests/test_manager_mode.py::TestCmsKyrTry::test_second_entry_ignored
```

### Observed failure

All three tests expect `kXR_redirect` (status 4004) after the mock CMS manager
sends a `kYR_select` or `kYR_try` frame. Instead the client receives
`kXR_ServerError` (status 4005):

```
AssertionError: expected kXR_redirect after kYR_select, got 4005
AssertionError: expected kXR_REDIRECT after kYR_try wake, got 4005
```

### What the tests do

Each test starts a mock CMS manager thread. The nginx worker connects to it, logs
in (sending `kYR_login`), then the test client sends `kXR_locate`. The worker
suspends the client session (`XRD_ST_WAITING_CMS`) and forwards a `kYR_locate`
frame to the mock CMS manager. The mock responds with either `kYR_select`
(single-host: `CMS_RR_SELECT = 10`) or `kYR_try` (ordered list:
`CMS_RR_TRY = 24`). The worker should wake the suspended session and send
`kXR_redirect` to the original client.

### Root cause area

`src/net/cms/recv.c` — `cms_wake_pending_session()` (line 10–60):

```c
xrd_ctx->state = XRD_ST_REQ_HEADER;
xrootd_send_redirect(xrd_ctx, client_conn, host, port);
xrootd_schedule_read_resume(client_conn);
return NGX_OK;
```

`xrootd_send_redirect` internally calls `xrootd_queue_response`, which calls
`c->send`. The function is called from the CMS connection's read event handler
(`ngx_xrootd_cms_read_handler`), operating on the *client* connection's
`xrootd_ctx_t`. This cross-connection send may fail if:

1. **`ctx->cur_streamid` mismatch** — `xrootd_send_redirect` uses
   `ctx->cur_streamid` to build the response header. After the locate was
   suspended, the streamid may have been cleared or overwritten in a way that
   doesn't match what the client expects.

2. **Pool allocation in wrong context** — `ngx_palloc(c->pool, total)` allocates
   from the client connection's pool. Under nginx's event model, touching another
   connection's pool from a different connection's read handler is safe only if
   the worker is single-threaded (which it is), but some internal nginx checks may
   reject the operation.

3. **`c->send` state** — The client connection's write event may be in a state
   (e.g., `wev->delayed`) that causes the first synchronous `c->send` attempt to
   fail with an unexpected code, triggering an error path that sends
   `kXR_ServerError` rather than retrying via `xrootd_schedule_write_resume`.

### Investigation steps

1. Add `ngx_log_error(NGX_LOG_WARN, ...)` before the
   `xrootd_send_redirect` call to log `xrd_ctx->cur_streamid[0]`,
   `xrd_ctx->cur_streamid[1]`, and `client_conn->fd`. Confirm the streamid
   matches the `kXR_locate` request streamid that the test sent.

2. Check the return value of `xrootd_send_redirect` in
   `cms_wake_pending_session`. Currently it is discarded. If it returns
   `NGX_ERROR`, an error is being sent from within the write path; log it.

3. Enable `error_log ... debug;` in the test nginx config and reproduce the
   failure. The write-helper at `src/protocols/root/connection/write_helpers.c:173` increments
   `response_write_errors_total` on write error — check `/metrics` for that
   counter.

4. Confirm whether the `kXR_ServerError` originates from
   `xrootd_send_redirect` failing mid-write or from the subsequent
   `xrootd_schedule_read_resume` resuming the session in a bad state.

### Fix sketch

After confirming the streamid is correct, the likely fix is to save the
`cur_streamid` at locate-dispatch time into the `xrootd_pending_locate_t` entry,
and restore it in `cms_wake_pending_session` before calling
`xrootd_send_redirect`:

```c
/* In xrootd_pending_locate_t (src/net/manager/pending.h): */
u_char  streamid[2];  /* client streamid at kXR_locate time */

/* In locate handler (src/protocols/root/read/locate.c), when adding to pending table: */
pending->streamid[0] = ctx->cur_streamid[0];
pending->streamid[1] = ctx->cur_streamid[1];

/* In cms_wake_pending_session (src/net/cms/recv.c): */
xrd_ctx->cur_streamid[0] = pending->streamid[0];
xrd_ctx->cur_streamid[1] = pending->streamid[1];
```

If the root cause is different (pool or write-event state), fix in
`xrootd_queue_response_base` (`src/protocols/root/connection/write_helpers.c`) to handle the
NGX_AGAIN case correctly when called from a non-client event context.

### Tests

`TestCmsSelectWake` and `TestCmsKyrTry` are already written. Once the fix is in
place, all three tests should pass without modification.

---

## 2. Upstream waitresp-then-redirect relay not forwarded

**Status:** Failing | **Effort:** Low–Medium | **Impact:** Medium

### Test

```
tests/test_a_upstream_redirect.py::TestUpstreamRedirect::test_locate_waitresp_then_redirect
```

### Observed failure

```
TimeoutError: timed out
tests/test_a_upstream_redirect.py:62: in _recv_exact
    chunk = sock.recv(n - len(buf))
```

The client never receives any response after sending the initial request.

### What the test does

An nginx instance is configured in upstream-redirect mode
(`xrootd_proxy_upstream`). The mock upstream sends the following sequence in
response to an open/locate request:

1. `kXR_waitresp` (dlen=0) — async acknowledgment
2. 100 ms pause
3. `kXR_redirect` with `target_host:target_port`

The client should receive both responses and ultimately see the redirect. The
test reads the first response (expects `kXR_waitresp`), then reads the second
(expects `kXR_redirect`).

### Root cause area

`src/net/proxy/forward_relay_response.c` — `xrootd_proxy_relay_to_client()`.

The `kXR_waitresp` path in the relay dispatch reads at line 183:

```c
if (status == kXR_wait
```

There is no explicit handling for `kXR_waitresp` (4006). Because `waitresp` is
not `kXR_ok`, `kXR_oksofar`, `kXR_wait`, or `kXR_redirect`, it likely falls
through to a path that resets state (`proxy->state = XRD_PX_IDLE`,
`ctx->state = XRD_ST_REQ_HEADER`) and discards the response without relaying it,
or worse, sends it once but then does not arm the upstream read event to receive
the subsequent redirect.

Check line ~183–230 for the waitresp case and confirm whether:
- `kXR_waitresp` is forwarded to the client, and
- the proxy then re-arms the upstream read event to receive the follow-up
  `kXR_redirect`.

### Fix sketch

Add a `kXR_waitresp` branch to `xrootd_proxy_relay_to_client` that:

1. Forwards the `kXR_waitresp` header (dlen=0) to the client.
2. Leaves `proxy->state = XRD_PX_READING_HDR` and does not transition to
   `XRD_PX_IDLE`, so the next upstream read delivers the `kXR_redirect`.

The pattern is analogous to the `kXR_oksofar` branch (line ~363) which also
continues reading rather than returning to idle.

### Tests

`test_locate_waitresp_then_redirect` is already written. No new tests needed.

---

## 3. Path depth guard returns wrong error codes

**Status:** Failing | **Effort:** Low | **Impact:** Low–Medium

### Tests

```
tests/test_path_depth_guards.py::test_normal_path_passes_depth_check
tests/test_path_depth_guards.py::test_deep_path_rejected_by_guard
tests/test_path_depth_guards.py::test_malicious_symlink_chain_blocked
```

### Observed failures

```
AttributeError: 'FileSystem' object has no attribute 'open'
AssertionError: expected kXR_ArgInvalid for depth violation, got 3013
    assert 3013 == 3000   (3013 = kXR_InvalidRequest)
AssertionError: malicious deep path must be rejected with ArgInvalid
    assert 3004 == 3000   (3004 = kXR_FileNotOpen)
```

There are two distinct problems: one in the test code and one in the
implementation.

### Problem A — test code bug (`test_normal_path_passes_depth_check`)

The test calls `fs.open(...)` on a `client.FileSystem` object:

```python
fs = client.FileSystem(ANON_URL)
status, body = fs.open(f"/{deep_dir}/test.txt", flags=client.OpenFlags.READ)
```

`client.FileSystem` does not have an `open` method — that belongs to
`client.File`. The XRootD Python binding for filesystem-level open is
`client.FileSystem.locate` (for locating) or `client.File` (for actually opening
a file handle). The test should either:

- Use `client.File` to open and verify that the open fails with `kXR_NotFound`
  (confirming the path was accepted but the file doesn't exist), or
- Use the raw socket helper `_raw_session()` + a manually built `kXR_open`
  frame — consistent with tests 2 and 3.

**Fix:** Replace `fs.open(...)` with:

```python
with _raw_session() as sock:
    _login_anon(sock, streamid=b"\x00\x03")
    shallow_path = _make_deep_path(5)
    payload = shallow_path.encode("utf-8")
    req = struct.pack("!2sH16sI", b"\x00\x03", kXR_OPEN_RD, b"\x00" * 16, len(payload))
    sock.sendall(req + payload)
    status, body = _read_response(sock)
assert status == kXR_ERROR, "shallow path should fail with NotFound not ArgInvalid"
assert _error_code(body) != kXR_ARG_INVALID, "shallow path must not be depth-rejected"
```

### Problem B — implementation: depth check returns silent null instead of kXR_ArgInvalid

`src/fs/path/resolve_path_variants.c` line 69–72:

```c
if (xrootd_count_path_depth(reqpath) != NGX_OK) {
    ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path depth exceeds limit");
    return 0;   /* ← returns NULL, not an error code */
}
```

When depth is exceeded, the function returns 0 (null path) rather than sending an
explicit `kXR_ArgInvalid` response. The callers that receive null handle it
inconsistently:

- `kXR_open` falls through to its normal "path not found" branch → returns
  `kXR_InvalidRequest` (3013, "query type not supported")
- `kXR_mkdir` falls through to its error branch → returns `kXR_FileNotOpen`
  (3004, "invalid file handle")

Neither of these is `kXR_ArgInvalid` (3000) as the tests require and as the wire
spec mandates for malformed-argument rejection.

**Fix options:**

Option A — return a sentinel from `resolve_path_variants`:

```c
/* Return a clearly invalid sentinel so callers can distinguish depth
 * rejection from "path not found". Define XROOTD_PATH_DEPTH_EXCEEDED
 * as a special value (e.g. (const char *)-1). */
if (xrootd_count_path_depth(reqpath) != NGX_OK) {
    return XROOTD_PATH_DEPTH_EXCEEDED;
}
```

Then each caller checks for `XROOTD_PATH_DEPTH_EXCEEDED` before its normal null
check and sends `kXR_ArgInvalid`.

Option B — let the depth check be the first call in each per-opcode handler
before `xrootd_resolve_path`, and have it send the error directly:

```c
/* In open handler (src/protocols/root/read/open_request.c), before resolve_path: */
if (xrootd_count_path_depth(reqpath) != NGX_OK) {
    return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                             "path exceeds maximum depth");
}
```

This avoids coupling the path-resolution function to response sending, which is
cleaner. The same two-line block needs to be inserted in:
- `src/protocols/root/read/open_request.c`
- `src/protocols/root/write/mkdir.c`
- `src/protocols/root/write/rm.c`
- `src/protocols/root/write/mv.c`
- Any other opcode handler that calls `xrootd_resolve_path` with untrusted paths

The `xrootd_count_path_depth` function already exists in
`src/fs/path/helpers.c:128` and `XROOTD_MAX_WALK_DEPTH` is defined in
`src/core/types/tunables.h:36`.

### Tests

Fix `test_normal_path_passes_depth_check` as described above. Tests 2 and 3
(`test_deep_path_rejected_by_guard`, `test_malicious_symlink_chain_blocked`) need
no changes once the implementation sends `kXR_ArgInvalid` correctly.

---

## 4. Infrastructure-dependent test failures

The following test failures require either a running reference xrootd HTTP server
or a specific network configuration not started by default. They are documented
here for completeness but are not implementation bugs in nginx-xrootd.

### 4a. xrdhttp comparison tests (7 tests)

```
tests/test_xrdhttp_auth.py (4 failures)
tests/test_xrdhttp_tpc.py  (2 failures)
tests/test_xrdhttp_webdav.py (1 failure)
```

**Root cause:** The tests compare nginx WebDAV (port 8443) against a reference
xrootd HTTP daemon that is expected on port 11113. `manage_test_servers.sh`
does not start this instance. `curl` returns exit code 58 (SSL certificate
problem) when connecting to nginx, and exit code 7 (connection refused) when
connecting to the reference daemon.

The SSL cert error (rc=58) for nginx suggests that `proxy_std.pem` is not
accepted as a valid client certificate by the test nginx TLS configuration — this
may be a separate bug. Two of the four `test_xrdhttp_auth.py` failures are test
code bugs: `TypeError: unsupported operand type(s) for +: 'CompletedProcess' and
'list'` and `TypeError: expected str, bytes or os.PathLike object, not tuple`
indicate malformed `subprocess.run` argument construction that is unrelated to
the server.

**What to investigate:**
- Add the reference xrootd HTTP instance to `manage_test_servers.sh` on port
  11113.
- Fix the two `subprocess.run` call sites in `test_xrdhttp_auth.py` (the
  `CompletedProcess + list` and `tuple` errors indicate the command argument is
  being built incorrectly — likely a missing `[...]` list wrapper or incorrect
  concatenation).
- Investigate whether `proxy_std.pem` is in a format nginx's TLS stack accepts
  as a client certificate.

### 4b. Interop query failures (8 tests)

```
tests/test_interop_query.py::TestQueryStats::test_qstats_ref_returns_nonempty
tests/test_interop_query.py::TestQuerySpace (2 tests)
tests/test_interop_query.py::TestQueryVisa (3 tests)
tests/test_interop_query.py::TestOpenFlagsConformance::test_open_append_mode_extends_file
tests/test_interop_query.py::TestErrorCodeFamilies::test_open_nonexistent_error_family_matches
```

**Root cause (mixed):**

- `test_qstats_ref_returns_nonempty` — the reference xrootd daemon returns an
  empty body for `kXR_Qstats`. Not an nginx bug.
- `TestQuerySpace` (2 tests) — the test parses the `kXR_Qspace` response as a
  plain key→value dict. The actual wire format is
  `oss.cgroup=<name>&oss.space=<n>&oss.free=<n>` — a single
  ampersand-delimited string. The test splits incorrectly, so `oss.free` appears
  as a substring of a dict value rather than a key. Fix: update the assertion to
  check `"oss.free=" in raw_response` rather than `"oss.free" in parts`.
- `TestQueryVisa` (3 tests) — both nginx and the reference return
  `kXR_InvalidRequest` ("Invalid information query type code"). Neither
  implements `kXR_Qvisa`. These tests are XFAILed correctly on the conformance
  matrix but not marked `@pytest.mark.xfail` in the test file. Add the mark, or
  remove the tests until `kXR_Qvisa` is implemented.
- `test_open_append_mode_extends_file` — `NameError: name '_read_all' is not
  defined`. The helper `_read_all` was referenced but never defined in the test
  module. Add the missing helper or replace the call with the equivalent inline
  code.
- `test_open_nonexistent_error_family_matches` — nginx returns `kXR_NotFound`
  family for opening a nonexistent path; reference returns `kXR_ArgInvalid`
  family. This is a deliberate behavior difference; the test should either be
  removed or marked `xfail` if the current nginx behavior is intentional.

### 4c. Interop namespace failures (2 tests)

```
tests/test_interop_namespace.py::TestMkdirConformance::test_rmdir_nonexistent_matches_reference
tests/test_interop_namespace.py::TestRmConformance::test_rm_directory_matches_reference
```

**Root cause:** nginx-xrootd returns an error for `rmdir` on a nonexistent
directory (matching POSIX) and for `rm` on a directory (also POSIX), while the
reference xrootd daemon returns success. These tests assert the two implementations
match. The discrepancy is a deliberate POSIX-vs-xrootd-leniency tradeoff. Either
change nginx to replicate the lenient reference behavior, or mark these tests
`xfail` documenting the divergence.

### 4d. Hanging tests (2 files)

```
tests/test_xrdcp_root_anon_compare.py
tests/test_xrootd_performance_conformance.py
```

**Root cause:** Both files use blocking calls (`subprocess.run` without
`timeout=`, `XRootD.client.File.open` via the XRootD Python bindings) that
cannot be interrupted by pytest's thread-based timeout mechanism. When the
reference xrootd server at the expected port is not responding, these calls block
indefinitely, causing the pytest timeout to fire but fail to kill the thread.

**Fix:** Add `timeout=` to each `subprocess.run` call
(`test_xrdcp_root_anon_compare.py:48`) and use the async XRootD Python API (or
wrap in a `threading.Timer`) in `test_xrootd_performance_conformance.py:258` so
that the blocking `f.open(...)` call can be terminated when the timeout fires.
Alternatively, switch pytest to the `signal` timeout method (requires Linux), or
add `@pytest.mark.skip` with a condition that skips when the reference server is
not reachable.

---

## Summary table

| # | Test(s) | Type | Effort | Root cause file |
|---|---------|------|--------|-----------------|
| 1 | `TestCmsSelectWake` + `TestCmsKyrTry` (3) | Implementation bug | Medium | `src/net/cms/recv.c:57` |
| 2 | `test_locate_waitresp_then_redirect` (1) | Implementation bug | Low | `src/net/proxy/forward_relay_response.c` |
| 3B | `test_deep_path_rejected_by_guard` + `test_malicious_symlink_chain_blocked` (2) | Implementation bug | Low | `src/fs/path/resolve_path_variants.c:71` |
| 3A | `test_normal_path_passes_depth_check` (1) | Test code bug | Trivial | `tests/test_path_depth_guards.py:151` |
| 4a | xrdhttp (4+2+1=7) | Infra + test code bugs | Low–Medium | `tests/test_xrdhttp_*.py` |
| 4b | interop_query (8) | Test code bugs + divergence | Low | `tests/test_interop_query.py` |
| 4c | interop_namespace (2) | Divergence | Trivial | `tests/test_interop_namespace.py` |
| 4d | xrdcp_compare, perf_conformance (2 files) | Test infra bug | Low | Hanging `subprocess.run` / `File.open` |

Implementation bugs total: **6 tests** across 3 source files.
Test code bugs and divergences: **18 tests** requiring test-only changes.

---

## Cross-cutting notes

- Run `PYTHONPATH=tests pytest tests/test_manager_mode.py -k "cms" -v --tb=long`
  with `error_log /tmp/xrd-test/logs/debug.log debug;` in the nginx config to
  get full trace for the CMS redirect failure.
- The `tests/test_a_upstream_redirect.py` fixture `upstream_waitresp_nginx`
  starts its own isolated nginx instance; changes to the proxy relay path require
  a `make` rebuild before the fixture picks them up.
- `src/fs/path/resolve_path_variants.c` is called by the resolve path in all three
  opcode families (read, write, namespace); any change to its null-return
  semantics must be validated across `src/protocols/root/read/open_request.c`,
  `src/protocols/root/write/mkdir.c`, `src/protocols/root/write/rm.c`, and `src/protocols/root/write/mv.c`.
