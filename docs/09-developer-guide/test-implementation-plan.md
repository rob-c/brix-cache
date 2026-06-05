# Test Implementation Plan

Companion to `missing-tests.md`. Converts the 55-test gap analysis into a phased,
effort-estimated implementation roadmap with per-task fixture dependencies, file
assignments, and ordering rationale.

Effort model calibrated from existing test files:
- `test_metrics.py` ~650 lines / 14 test methods ≈ 45 lines per test
- `test_manager_mode.py` ~1242 lines / 28 test methods ≈ 44 lines per test
- `test_webdav.py` ~1154 lines / 22 test methods ≈ 52 lines per test
- `test_s3.py` ~523 lines / 11 test methods ≈ 47 lines per test
- A new test file from scratch adds ~80–120 lines of fixture/setup overhead

Estimate key:
- S = Simple (label check, basic assert) — ~30 min, 20–30 lines
- M = Medium (subprocess + delta check) — ~1 hour, 35–55 lines
- H = Hard (auth setup, concurrency, TPC, XML parsing) — 1.5–2.5 hours, 60–100 lines
- NF = New file overhead — 1.5–2 hours, 80–120 lines

---

## Total effort summary

| Phase | Sections | Tests | Est. hours | Risk |
|-------|----------|-------|------------|------|
| 1 — Stream metric additions | 1, 2, 3, 7, 8 | 19 | 17.5 h | Low |
| 2 — Per-IP-version bytes | 4 | 6 | 4.5 h | Low |
| 3 — WebDAV metrics (new file) | 5 | 11 | 11 h | Medium |
| 4 — S3 metrics (new file) | 6 | 10 | 10 h | Medium |
| 5 — WebDAV + S3 e2e additions | 10, 11 | 12 | 12.5 h | Low |
| 6 — Redirector e2e (new file) | 9 | 9 | 14 h | Medium |
| 7 — Large file + metrics (new file) | 12 | 5 | 10 h | Low |
| **Total** | | **72** | **79.5 h** | |

All phases are independent except where noted in the dependency column. Phase 1 should
be done first since it validates the metric instrumentation fixes that Phases 2–7 rely on.

---

## Phase 1 — Stream metric additions

**Target file:** `tests/test_metrics.py`
**Prerequisites:** No new infrastructure. All ports already started by `manage_test_servers.sh`.
**Total phase estimate:** 17.5 hours

### Section 1 — Prometheus label correctness

Add to class `TestMetricsEndpoint`.

| ID | Test | Effort | Lines | Fixtures | Notes |
|----|------|--------|-------|----------|-------|
| 1a | All 38 op names present and distinct | S — 30 min | 25 | `metrics_url` (existing) | Assert `op="query_space"` distinct from `op="query_cksum"`. Catches regression to slot-17 collision. |
| 1b | `query_space` counter increments independently | M — 1 h | 40 | `anon_port`, `metrics_url` | Baseline both counters; `subprocess.run(["xrdfs", ..., "spaceinfo", "/"])`; assert space delta ≥ 1, cksum delta == 0. |
| 1c | `readv` counter increments after vector read | H — 1.5 h | 55 | `anon_port`, writable test file | Use `xrootd` Python client `XRootD.client.File.vector_read()` to issue readv; assert `op="readv"` delta ≥ 1 and NOT credited to `query_space`. |

**Dependency:** 1b and 1c depend on 1a passing (proves label names are correct before testing deltas).

### Section 2 — Error counters

Add class `TestErrorCounters` to `test_metrics.py`.

| ID | Test | Effort | Lines | Fixtures | Notes |
|----|------|--------|-------|----------|-------|
| 2a | Failed GSI login → op_err{op="login"} | H — 1.5 h | 65 | `gsi_port`, expired proxy | Generate expired proxy with `grid-proxy-init -valid 0:0`; attempt connect; assert err delta ≥ 1. If PKI tooling unavailable, use a cert with wrong CA. |
| 2b | Write to read-only server → op_err{op="open_wr"} | M — 45 min | 40 | `readonly_port`, `metrics_url` | `xrdcp` a 1-byte file to `root://localhost:READONLY_PORT//x.txt`; assert non-zero rc; assert `open_wr` err delta ≥ 1. Readonly server already configured. |
| 2c | stat non-existent file → op_err{op="stat"} | S — 30 min | 25 | `anon_port`, `metrics_url` | `xrdfs stat /no_such_file_42`; assert `op="stat"` err delta ≥ 1. |
| 2d | CMS-suspended data server rejects login | H — 1.5 h | 70 | `cluster` fixture (module-scoped, pre-launched) | Use cluster fixture `ds_port`; instruct manager to suspend via wire; connect directly to ds_port; assert op_err{op="login"} increments. Requires suspend API or manual conf flag. |

**Dependency:** 2d requires the `cluster` fixture from `test_manager_mode.py`. Import it or move to a shared conftest.

### Section 3 — Byte count accuracy

Add to class `TestAnonCounters`.

| ID | Test | Effort | Lines | Fixtures | Notes |
|----|------|--------|-------|----------|-------|
| 3a | bytes_rx delta in [N, N×1.1] for write | S — 30 min | 20 | `anon_port`, `metrics_url` | Extend `test_write_increments_bytes_rx`; assert `delta <= payload * 1.1`. |
| 3b | bytes_tx delta in [N, N×1.1] for read | S — 30 min | 25 | `anon_port`, `metrics_url` | Write known payload; xrdcp read; assert delta close. |
| 3c | Concurrent uploads accumulate correctly | H — 1 h | 60 | `anon_port`, `metrics_url` | Two `subprocess.Popen` xrdcp simultaneously (32 KB each); wait both; assert delta ≥ 65536. Tests atomic add correctness. |
| 3d | connections_active reaches 0 after disconnect | M — 45 min | 35 | `anon_port`, `metrics_url` | Wait 500 ms after last transfer; assert `connections_active{port=ANON_PORT}` == 0. Catches gauge leak at session open. |

### Section 7 — Token and auth counters

Add class `TestTokenCounters` to `test_metrics.py`.

| ID | Test | Effort | Lines | Fixtures | Notes |
|----|------|--------|-------|----------|-------|
| 7a | Token login → op_ok{op="login"} on token port | M — 45 min | 40 | `token_port` (11097), valid JWT fixture | Use existing token fixture; xrdcp with `XrdSecSSSKT=` env var; assert login ok delta ≥ 1. |
| 7b | Expired JWT → op_err{op="auth"} | H — 1.5 h | 65 | `token_port`, expired JWT | Craft expired token (standard `iat`/`exp` fields); connect; assert auth err delta ≥ 1. JWT can be generated with `python-jwt` library (already in requirements for token tests). |
| 7c | GSI cert-ok path → stream auth_total | M — 1 h | 45 | `gsi_port`, valid proxy | `xrdcp` with valid proxy to gsi_port; assert `xrootd_auth_total{result="cert_ok"}` delta ≥ 1. |

### Section 8 — TPC and prepare op counters

Add class `TestAdvancedOpCounters` to `test_metrics.py`.

| ID | Test | Effort | Lines | Fixtures | Notes |
|----|------|--------|-------|----------|-------|
| 8a | kXR_prepare op_ok after prepare request | M — 1 h | 45 | `anon_port`, `metrics_url`, test file | `xrdfs root://localhost:ANON_PORT/ prepare /data/test.txt`; assert `op="prepare"` ok delta ≥ 1. |
| 8b | kXR_prepare op_err on empty path list | H — 1.5 h | 60 | `anon_port`, `metrics_url` | Requires sending raw wire frame with empty prepare list. Use `XRootD.client` low-level query or craft bytes directly via `socket`. Assert `op="prepare"` err delta ≥ 1. |
| 8c | query_stats op_ok after xrdfs spaceinfo | S — 30 min | 25 | `anon_port`, `metrics_url` | `xrdfs spaceinfo /`; assert delta ≥ 1. |
| 8d | query_xattr op_ok after xattr query | M — 45 min | 35 | `anon_port`, `metrics_url` | `xrdfs xattr /data/test.txt` or raw kXR_query/kXR_QXAttr; assert delta ≥ 1. |
| 8e | locate op_ok after xrdfs locate | S — 30 min | 25 | `anon_port`, `metrics_url` | `xrdfs locate /data/test.txt`; assert delta ≥ 1. |

---

## Phase 2 — Per-IP-version bytes

**Target file:** `tests/test_metrics.py` — add class `TestIpVersionBytes`
**Prerequisites:** Phase 1 Section 1 complete (confirms label names before asserting deltas).
**Total phase estimate:** 4.5 hours

The four `bytes_rx/tx_ipv4/ipv6_total` counters were broken (tracked request count
instead of bytes). These tests verify the fix is both correct and not regressed.

| ID | Test | Effort | Lines | Fixtures | Protocol |
|----|------|--------|-------|----------|----------|
| 4a | xrootd bytes_tx_ipv4_total on GET (IPv4) | M — 45 min | 45 | `anon_port` via 127.0.0.1 | XRootD stream |
| 4b | xrootd bytes_rx_ipv4_total on PUT (IPv4) | M — 45 min | 45 | `anon_port` via 127.0.0.1 | XRootD stream |
| 4c | webdav bytes_tx_ipv4_total on GET | M — 45 min | 45 | `http_webdav_port`, curl | WebDAV HTTP |
| 4d | webdav bytes_rx_ipv4_total on PUT (not +1) | M — 45 min | 45 | `http_webdav_port`, curl | WebDAV HTTP |
| 4e | s3 bytes_tx_ipv4_total on GetObject | M — 45 min | 45 | `s3_url`, `requests` | S3 |
| 4f | s3 bytes_rx_ipv4_total on PutObject (not +1) | M — 45 min | 45 | `s3_url`, `requests` | S3 |

**Key assertion pattern** (same for all six):
```python
before = get_metric("xrootd_webdav_bytes_rx_ipv4_total")
# ... perform transfer of PAYLOAD_SIZE bytes ...
after = get_metric("xrootd_webdav_bytes_rx_ipv4_total")
delta = after - before
assert delta >= PAYLOAD_SIZE, "counter not accumulating bytes"
assert delta != 1, "counter is counting requests, not bytes (old bug)"
assert delta <= PAYLOAD_SIZE * 1.2, "counter over-counting"
```

**IPv6 note:** IPv6 tests (4g, 4h potential additions) require the test host to have
a configured `::1` loopback and the nginx listener to bind `[::1]` in addition to
`0.0.0.0`. Defer until IPv6 listener support is confirmed in the test config.

---

## Phase 3 — WebDAV metrics (new file)

**Target file:** `tests/test_webdav_metrics.py` (new)
**Prerequisites:** Existing WebDAV server at `HTTP_WEBDAV_PORT` (8443) running.
**Total phase estimate:** 11 hours (including ~1.5 h new-file setup)

**New file skeleton:**
```python
import os, hashlib, subprocess, requests
import pytest
from conftest import get_metric_value, http_webdav_port, gsi_port

METRICS_URL = f"http://localhost:{METRICS_PORT}/metrics"

def _curl(*args):
    return subprocess.run(["curl", "-sf", *args], capture_output=True)

def _webdav_url(path):
    return f"http://localhost:{HTTP_WEBDAV_PORT}{path}"

class TestWebDAVRequestCounters:
    ...

class TestWebDAVByteCounters:
    ...

class TestWebDAVAuthCounters:
    ...

class TestWebDAVTPC:
    ...
```

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 5a | GET → webdav_requests_total{method="GET"} | M — 45 min | 40 | `_curl("-X", "GET", url)` |
| 5b | PUT → requests_total + bytes_rx_total | M — 45 min | 45 | `_curl("-T", tmpfile, url)` |
| 5c | PROPFIND → requests_total + bytes_tx_total | M — 1 h | 50 | Measure response body size via `curl -w %{size_download}` |
| 5d | PROPFIND bytes_tx_ipv4 also increments | S — 30 min | 20 | Extend 5c with ipv4 counter check |
| 5e | DELETE → requests_total{method="DELETE"} | S — 30 min | 25 | PUT then DELETE; assert delta ≥ 1 |
| 5f | MKCOL → requests_total{method="MKCOL"} | S — 30 min | 25 | MKCOL + cleanup |
| 5g | 404 → responses_total{status="4xx"} | S — 30 min | 25 | GET /nonexistent_path |
| 5h | Auth counters: anon, cert, token | H — 2 h | 80 | Three separate requests; each requires appropriate auth fixture. GSI needs valid proxy, token needs JWT fixture. Assert three distinct `auth_total` labels. |
| 5i | Multipart-range GET → bytes_tx_ipv4 | H — 1.5 h | 65 | `Range: bytes=0-1023, 2048-3071`. Use `curl -H "Range: ..."`. Parse response for multipart boundary. Assert per-IP delta equals sum of ranges. |
| 5j | TPC pull started and success counters | H — 2 h | 80 | Requires a second WebDAV-accessible server as TPC source. Use localhost HTTP server as source. `COPY` with `Source:` header. Assert `tpc_total{event="pull_started"}` and `{event="pull_success"}`. |
| 5k | TPC bad-request counter on COPY without Source | M — 45 min | 35 | COPY without `Source:` header; assert `tpc_total{event="bad_request"}` delta ≥ 1. |

**Known risk:** Test 5j (TPC) requires a simple HTTP source server. Use Python's
`http.server` launched in a subprocess as the TPC source. This is the same pattern
used in `test_tpc.py`; reuse that fixture approach.

---

## Phase 4 — S3 metrics (new file)

**Target file:** `tests/test_s3_metrics.py` (new)
**Prerequisites:** S3 server running at `S3_PORT` (9001). `requests` library (already in requirements).
**Total phase estimate:** 10 hours (including ~1.5 h new-file setup)

**Existing S3 test pattern** (from `test_s3.py`):
```python
S3_URL = f"http://localhost:{S3_PORT}"

def _obj_url(key):
    return f"{S3_URL}/bucket/{key}"

def _s3_put(key, body, headers=None):
    return requests.put(_obj_url(key), data=body, headers=headers or {})

def _s3_get(key):
    return requests.get(_obj_url(key))
```

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 6a | GetObject → s3_requests_total{method="GET"} and responses 2xx | M — 45 min | 45 | PUT an object first; GET it; assert both counters. |
| 6b | PutObject → requests_total + bytes_rx_total | M — 45 min | 45 | PUT 16 KB; assert request counter and bytes_rx delta. |
| 6c | ListObjectsV2 → requests_total + list_contents_total | H — 1 h | 55 | PUT 3 objects; LIST; assert list_contents_total delta == 3. This validates the `list_objects_v2.c` fix. |
| 6d | List with delimiter → list_common_prefixes_total | M — 45 min | 45 | PUT `dir/a.txt`, `dir/b.txt`, `other.txt`; LIST with `delimiter=/`; assert prefix delta == 1. |
| 6e | Paginated list → list_truncated_total | M — 45 min | 40 | PUT 3 objects; LIST with `max-keys=1`; assert truncated delta == 1. |
| 6f | PutObject bytes_rx_ipv4 accumulates (not +1) | M — 45 min | 45 | PUT 32 KB; assert delta ≥ 32768 AND delta ≠ 1. |
| 6g | GetObject bytes_tx_ipv4 accumulates | M — 45 min | 45 | GET 32 KB object; assert delta ≥ 32768. |
| 6h | Bad SigV4 → auth_total{result="sig_mismatch"} | H — 1.5 h | 65 | Send GET with `Authorization: AWS4-HMAC-SHA256 Credential=BADKEY/...`; assert 403 and auth counter. Requires crafting a syntactically valid but semantically wrong SigV4 header. |
| 6i | DeleteObject → requests_total{method="DELETE"} | S — 30 min | 25 | PUT; DELETE; assert counter. |
| 6j | GET missing key → responses_total{status="4xx"} | S — 30 min | 25 | GET a key that does not exist; assert 404 counter. |

---

## Phase 5 — WebDAV and S3 e2e additions

**Target files:** `tests/test_a_webdav_clients.py` (extend), `tests/test_s3.py` (extend)
**Prerequisites:** Sections 5 and 6 complete (or can run independently — no functional dependency).
**Total phase estimate:** 12.5 hours

### Section 10 — WebDAV e2e additions

Add to `tests/test_a_webdav_clients.py`.

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 10a | xrdcp davs:// byte-exact hash comparison | S — 30 min | 25 | Extend existing `test_xrdcp_upload_and_download`; add `md5(downloaded) == md5(original)`. |
| 10b | curl PUT → xrdcp GET cross-client round-trip | M — 1 h | 50 | curl to HTTP port, xrdcp from davs:// port, assert hash. Exercises shared namespace. |
| 10c | PROPFIND depth-1 returns correct file count | H — 1.5 h | 70 | PUT 3 files; PROPFIND; parse XML `<D:response>` count. Use `xml.etree.ElementTree` or `lxml`. Assert count == 4. |
| 10d | WebDAV COPY (server-side) preserves bytes | M — 1 h | 50 | PUT; COPY Destination header; GET copy; assert hash. |
| 10e | DELETE removes file; subsequent GET → 404 | S — 30 min | 30 | PUT; DELETE; GET; assert 404 status. |

### Section 11 — S3 e2e additions

Add to `tests/test_s3.py` (or new `tests/test_s3_e2e.py` if the file is already
large).

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 11a | PutObject → GetObject byte-exact | S — 30 min | 30 | `os.urandom(65536)` round-trip; assert bytes equal. |
| 11b | Multipart upload → GetObject byte-exact | H — 2 h | 90 | InitiateMultipart; 3 UploadPart (5 MB each); CompleteMultipart; GetObject; assert MD5. Requires the S3 multipart API sequence. |
| 11c | ListObjectsV2 correct key names and sizes | M — 1 h | 55 | PUT objects with specific names; LIST; parse XML; assert each key and size present. |
| 11d | HeadObject returns correct Content-Length | S — 30 min | 30 | PUT known-size object; HEAD; assert Content-Length == size. |
| 11e | DeleteObject removes object | S — 30 min | 30 | PUT; DELETE; HEAD; assert 404. |
| 11f | CopyObject preserves content | M — 1 h | 50 | PUT source; CopyObject to destination; GET dest; assert hash matches source. |
| 11g | Presigned URL GET works without credentials | H — 1.5 h | 70 | Generate presigned URL via `requests` + SigV4 pre-signing. `requests.get(url)` with no auth headers; assert 200 and correct content. May need AWS SDK or manual pre-signing. |

---

## Phase 6 — Redirector e2e (new file)

**Target file:** `tests/test_e2e_redirector_xrdcp.py` (new)
**Prerequisites:**
- Cluster fixture accessible (available in `test_manager_mode.py`; move to `conftest.py` or import)
- `xrdcp` binary on PATH
- `hashlib` for MD5 comparison
**Total phase estimate:** 14 hours (including ~2 h new-file + fixture setup)

This is the highest-value section: no existing test exercises the full
nginx-redirector → xrootd-data-server → xrdcp data transfer path.

**Fixture plan:**
```python
@pytest.fixture(scope="module")
def redirector(tmp_path_factory):
    """Returns (redir_port, ds_port, data_root) from the pre-launched cluster."""
    # Re-use constants from manage_test_servers.sh:
    # CLUSTER_REDIR_PORT=11130, CLUSTER_DS_PORT=11132
    redir_port = int(os.environ.get("CLUSTER_REDIR_PORT", 11130))
    ds_port    = int(os.environ.get("CLUSTER_DS_PORT",   11132))
    data_root  = os.environ.get("CLUSTER_DS_DATA", "/tmp/xrd-test/cluster-data")
    # Wait for both ports to be ready (same pattern as conftest.py wait_for_port)
    wait_for_port("localhost", redir_port, timeout=10)
    wait_for_port("localhost", ds_port,    timeout=10)
    return SimpleNamespace(redir_port=redir_port, ds_port=ds_port, data_root=data_root)
```

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 9a | xrdcp read through redirector — byte-exact | M — 1 h | 55 | Write file to `data_root`; `xrdcp root://localhost:redir_port//file /tmp/out`; MD5 compare. Core happy-path test. |
| 9b | xrdcp write through redirector → file on DS | M — 1 h | 55 | `xrdcp /tmp/src.bin root://localhost:redir_port//uploads/x.bin`; assert file at `data_root/uploads/x.bin` matches source. |
| 9c | 200 MB round-trip preserves integrity | H — 1.5 h | 65 | Pre-create `/tmp/xrd-test/data/large200.bin` in conftest (session-scoped); xrdcp download; MD5. Mark `@pytest.mark.slow`. |
| 9d | xrdfs stat through redirector returns correct metadata | M — 45 min | 40 | `subprocess.run(["xrdfs", ..., "stat", "/data/test.txt"])`; assert `Size:` in stdout and correct byte count. |
| 9e | xrdfs ls through redirector lists correct directory | M — 45 min | 40 | Write 3 files; `xrdfs ls /data/`; assert all 3 names in output. |
| 9f | Parallel downloads all succeed (5 concurrent) | H — 1.5 h | 70 | Five `subprocess.Popen` xrdcp simultaneously; wait all (timeout=60s); assert all rc == 0 and all MD5 match. |
| 9g | GSI auth xrdcp through redirector | H — 1.5 h | 65 | Set `X509_USER_PROXY`; xrdcp to GSI redirector port (if cluster has GSI listener); assert success. Skipped if GSI cluster port not configured. |
| 9h | Redirector metrics update after client transfer | M — 1 h | 55 | Baseline `connections_total` + `op_ok{op="login"}` on `redir_port`; run xrdcp; assert both increment. Redirector handshake is counted even though data flows via DS. |
| 9i | xrdcp TPC through redirector | H — 2 h | 85 | Source via `root://localhost:redir_port//src.bin`; destination a second xrootd or anon port. `xrdcp root://redir//src.bin root://anon//dst.bin`. Assert dst MD5 matches src. |

**Ordering within phase:** 9a and 9b first (validates fixture). Then 9d, 9e (read-only metadata).
Then 9h (metrics integration). Then 9f (parallel). 9c, 9i are slow/complex — do last.
9g is conditional on GSI cluster configuration — can be skipped with `@pytest.mark.skipif`.

---

## Phase 7 — Large file and metrics integration (new file)

**Target file:** `tests/test_large_file_metrics.py` (new)
**Prerequisites:**
- All metrics label tests from Phase 1 complete (so label names are confirmed before asserting large-delta values)
- A 200 MB test file pre-created in conftest (session fixture to avoid repeated creation)
**Total phase estimate:** 10 hours (including ~1.5 h new-file setup + conftest addition)

**Session fixture to add to `conftest.py`:**
```python
@pytest.fixture(scope="session")
def large_file_200mb(tmp_path_factory):
    p = tmp_path_factory.getbasetemp() / "large200.bin"
    if not p.exists():
        with open(p, "wb") as f:
            for _ in range(200):
                f.write(os.urandom(1024 * 1024))
    return p, hashlib.md5(p.read_bytes()).hexdigest()
```

Mark all tests in this file with `@pytest.mark.slow` to allow `pytest -m "not slow"` to skip them.

| ID | Test | Effort | Lines | Notes |
|----|------|--------|-------|-------|
| 12a | 200 MB xrdcp download — byte-exact + metrics delta | H — 2 h | 75 | Baseline `bytes_tx_total`; xrdcp; assert rc == 0, MD5 match, and `200*MiB <= delta <= 220*MiB`. |
| 12b | 200 MB xrdcp upload — byte-exact + metrics delta | H — 2 h | 75 | xrdcp upload; assert file exists with correct size; assert `bytes_rx_total` delta in range. |
| 12c | Large WebDAV PUT then GET byte-exact | H — 1.5 h | 65 | `curl -T large200.bin http://...`; `curl -o out.bin http://...`; assert MD5. May need increased curl timeout. |
| 12d | Large S3 PutObject byte-exact | H — 1.5 h | 65 | `requests.put(url, data=open(large_file, "rb"))`; GET back; assert MD5. Watch for `requests` streaming upload pattern. |
| 12e | CRC32c checksum matches independently computed | H — 1.5 h | 65 | `import crc32c`; compute local; `xrdfs query checksum /large200.bin`; parse `crc32c:HEX`; assert match. Requires `crc32c` package in requirements.txt (already present per imports in compat layer). |

---

## Implementation order and dependencies

```
Phase 1 (stream metrics)        → validates instrumentation fixes
  └─ Phase 2 (per-IP bytes)     → confirms Pattern 4 fix works
  └─ Phase 3 (WebDAV metrics)   → confirms WebDAV counters correct
  └─ Phase 4 (S3 metrics)       → confirms S3 counters correct
       └─ Phase 5 (e2e round-trips) → validates correctness at protocol level
  └─ Phase 6 (redirector e2e)   → validates redirect chain end-to-end
       └─ Phase 7 (large file)  → validates scale and byte accuracy
```

Phases 2, 3, 4, and 6 can run concurrently after Phase 1 completes.
Phases 5 and 7 can run concurrently after their respective prerequisites.

---

## Fixtures to add or promote to conftest.py

| Fixture | Currently in | Action |
|---------|-------------|--------|
| `cluster` (nginx manager + DS) | `test_manager_mode.py` | Move to `conftest.py`; needed by sections 2d and 9 |
| `large_file_200mb` (session) | does not exist | Add to `conftest.py` |
| `expired_jwt` | does not exist | Add to `conftest.py` or `fixtures/pki.py` |
| `expired_proxy` | does not exist | Add to `conftest.py` or `fixtures/pki.py`; needs `voms-proxy-init` or `grid-proxy-init` |
| `http_server` (TPC source) | `test_tpc.py` (local copy) | Extract to `conftest.py` for reuse in section 5j |

---

## New files to create

| File | Phase | Lines (est.) | Purpose |
|------|-------|--------------|---------|
| `tests/test_webdav_metrics.py` | 3 | ~550 | WebDAV Prometheus metric coverage |
| `tests/test_s3_metrics.py` | 4 | ~480 | S3 Prometheus metric coverage |
| `tests/test_e2e_redirector_xrdcp.py` | 6 | ~550 | nginx redirector → xrootd e2e |
| `tests/test_large_file_metrics.py` | 7 | ~380 | Large file correctness + metrics bounds |

---

## pytest.ini markers to add

```ini
[pytest]
markers =
    slow: marks tests as slow (deselect with -m "not slow")
    e2e: marks full end-to-end tests requiring cluster and xrdcp
    large: marks tests using large (200 MB) test files
```

Slow/e2e/large tests will be excluded from the standard `pytest tests/ -v` run used
during development and included in a nightly or pre-merge CI step.

---

## Requirements additions

| Package | Version | Used by |
|---------|---------|---------|
| `crc32c` | ≥1.5 | 12e |
| `lxml` | ≥4.9 | 10c (XML parse; stdlib `xml.etree` is acceptable fallback) |

Both are optional — the tests can be skipped if the package is absent via
`pytest.importorskip("crc32c")`.
