# Missing Tests — nginx-xrootd

Identified gaps in the test suite as of 2026-05-27. Organized from lowest-level
(metric label correctness) to highest-level (full xrdcp round-trip through nginx acting
as a CMS redirector in front of a real xrootd data server).

Each entry names the test, states what it verifies, explains why it matters, gives
the scenario steps, and lists the key assertions. The suggested file name is where
each test logically belongs.

---

## Table of contents

1. [Prometheus metrics — label correctness](#1-prometheus-metrics--label-correctness)
2. [Prometheus metrics — error counters](#2-prometheus-metrics--error-counters)
3. [Prometheus metrics — byte count accuracy](#3-prometheus-metrics--byte-count-accuracy)
4. [Prometheus metrics — per-IP-version bytes](#4-prometheus-metrics--per-ip-version-bytes)
5. [Prometheus metrics — WebDAV protocol layer](#5-prometheus-metrics--webdav-protocol-layer)
6. [Prometheus metrics — S3 protocol layer](#6-prometheus-metrics--s3-protocol-layer)
7. [Prometheus metrics — token and auth counters](#7-prometheus-metrics--token-and-auth-counters)
8. [Prometheus metrics — TPC and prepare ops](#8-prometheus-metrics--tpc-and-prepare-ops)
9. [End-to-end: nginx redirector → xrootd data server](#9-end-to-end-nginx-redirector--xrootd-data-server)
10. [End-to-end: high-level WebDAV round-trip](#10-end-to-end-high-level-webdav-round-trip)
11. [End-to-end: high-level S3 round-trip](#11-end-to-end-high-level-s3-round-trip)
12. [End-to-end: large file integrity and metrics](#12-end-to-end-large-file-integrity-and-metrics)

---

## 1. Prometheus metrics — label correctness

**File:** `tests/test_metrics.py` — add to `TestMetricsEndpoint`

### 1a. All query-op labels are present and correctly named

**What it verifies:** Every `op=` label in the Prometheus output matches the constant
name it was compiled against — specifically that `query_cksum` and `query_space` are
distinct labels at consecutive slots, and that `readv`, `pgread`, `writev`, `locate`,
`statx`, `fattr`, `query_stats`, `query_xattr`, `query_finfo`, `query_fsinfo`, `set`,
`query_visa`, `query_opaque`, `query_ckscan`, `clone`, `chkpoint`, `prepare` all
appear.

**Why it matters:** The slot-collision bug (QUERY_SPACE = QUERY_CKSUM = 17) made every
label from `readv` onwards one position wrong. The existing `test_all_op_names_present`
only checks the first 17 ops; it would not have caught this.

**Scenario:** Fetch `/metrics`, check for each expected op label.

**Assertions:**
```python
ops_full = [
    "login", "auth", "stat", "open_rd", "open_wr", "read", "write", "sync",
    "close", "dirlist", "mkdir", "rmdir", "rm", "mv", "chmod", "truncate",
    "ping", "query_cksum", "query_space", "readv", "pgread", "writev",
    "locate", "statx", "fattr", "query_stats", "query_xattr", "query_finfo",
    "query_fsinfo", "set", "query_visa", "query_opaque", "query_opaquf",
    "query_opaqug", "query_ckscan", "clone", "chkpoint", "prepare",
]
for op in ops_full:
    assert f'op="{op}"' in text
# query_cksum and query_space must both be present (not merged)
assert text.count('op="query_cksum"') >= 1
assert text.count('op="query_space"') >= 1
```

### 1b. query_space counter increments independently of query_cksum

**What it verifies:** An `xrdfs spaceinfo` call (kXR_query / kXR_QSpace) increments
`op_ok{op="query_space"}` and does NOT increment `op_ok{op="query_cksum"}`.

**Why it matters:** The slot collision caused space queries to be credited to the cksum
slot. This test catches any regression to that state.

**Scenario:**
1. Baseline both counters.
2. Run `xrdfs root://localhost:ANON_PORT/ spaceinfo /`.
3. Assert `query_space` delta ≥ 1; assert `query_cksum` delta == 0.

### 1c. readv counter increments after a vector read

**What it verifies:** A `kXR_readv` operation increments `op_ok{op="readv"}`, not
`op_ok{op="query_space"}` (which was the wrong label before the fix).

**Scenario:** Open a file with `xrootd` Python API and call `readv()` directly, or use
`xrdfs` with `--posc-read`. Assert delta on `readv` label.

---

## 2. Prometheus metrics — error counters

**File:** `tests/test_metrics.py` — add new class `TestErrorCounters`

### 2a. Failed GSI login increments op_err{op="login"}

**What it verifies:** Connecting with an expired or revoked proxy certificate causes
`op_err{op="login"}` to increment on the GSI server. The counter was never written
before the fix to `session/login.c`.

**Scenario:**
1. Generate an expired proxy (validity 0 seconds) or use a self-signed cert not in the CA bundle.
2. Baseline `xrootd_requests_total{op="login", status="err"}` on GSI port.
3. Attempt `xrdcp` with the bad credential; expect non-zero exit code.
4. Assert delta ≥ 1.

### 2b. Write to read-only server increments op_err{op="open_wr"}

**What it verifies:** An `xrdcp` PUT against the read-only server returns an error and
that error is reflected in `op_err{op="open_wr"}`, not silently dropped.

**Scenario:**
1. Baseline the read-only server's metrics.
2. `xrdcp` a file to `root://localhost:READONLY_PORT//test.txt`.
3. Assert `xrdcp` returns non-zero.
4. Assert `op_err{op="open_wr"}` delta ≥ 1.

### 2c. stat on non-existent file increments op_err{op="stat"}

**What it verifies:** `xrdfs stat /nonexistent` increments `op_err{op="stat"}`.

**Scenario:** Run `xrdfs root://localhost:ANON_PORT/ stat /no_such_file_exists`, assert
delta on `op_err{op="stat"}` ≥ 1.

### 2d. CMS-suspended server rejects login and increments op_err

**What it verifies:** When the manager suspends a data server, clients hitting that
server's port get a login rejection that is counted.

**Scenario:** Use the cluster fixture; instruct the manager to suspend, then connect
directly to the data-server port. Assert `op_err{op="login"}` increments.

---

## 3. Prometheus metrics — byte count accuracy

**File:** `tests/test_metrics.py` — extend `TestAnonCounters`

### 3a. bytes_rx delta matches write payload within 10%

**What it verifies:** The existing `test_write_increments_bytes_rx` only asserts
`delta >= len(payload)`. This test additionally asserts the delta is not wildly over
(which would indicate double-counting). The acceptable window is `[N, N * 1.1]` to
account for framing overhead.

**Scenario:** Write a 65536-byte payload, assert `bytes_rx_total` delta is between
65536 and 72000.

### 3b. bytes_tx delta matches read payload within 10%

**Same approach for reads.** Write a known payload, read it back, assert `bytes_tx_total`
delta is close to the payload size.

### 3c. Multiple concurrent transfers — byte totals are additive

**What it verifies:** Two simultaneous `xrdcp` uploads accumulate correctly in the
shared-memory atomic counter.

**Scenario:** Spawn two `subprocess.Popen` xrdcp writes simultaneously (same server,
different filenames, 32 KB each). Wait for both to complete. Assert `bytes_rx_total`
delta ≥ 65536.

### 3d. connections_active reaches zero after all clients disconnect

**What it verifies:** The active-connection gauge is correctly decremented to zero
(not just "not higher than before") after a known starting state.

**Why it matters:** The existing test checks "doesn't increase" but not "goes to zero".
A stuck connection leaking at session start would be invisible to the existing check.

**Scenario:**
1. Confirm no xrdcp processes are running.
2. Wait 500ms for in-flight sessions to finish.
3. Fetch metrics; assert `xrootd_connections_active{port=ANON_PORT} == 0` (or label absent, which also means zero).

---

## 4. Prometheus metrics — per-IP-version bytes

**File:** `tests/test_metrics.py` — add new class `TestIpVersionBytes`

These tests verify the counters introduced in the metrics bug fix (Pattern 4 in
`docs/08-metrics-monitoring/metrics-bug-patterns.md`). Before the fix, these counters
tracked request count, not bytes.

### 4a. xrootd bytes_tx_ipv4_total accumulates on GET (IPv4 client)

**Scenario:**
1. Baseline `xrootd_bytes_tx_ipv4_total{port=ANON_PORT}`.
2. `xrdcp` a known-size file from `root://127.0.0.1:ANON_PORT//...` (IPv4 loopback).
3. Assert delta ≥ payload size.
4. Assert `bytes_tx_ipv6_total` delta == 0 (no IPv6 traffic on this transfer).

### 4b. xrootd bytes_rx_ipv4_total accumulates on PUT (IPv4 client)

Same approach for uploads.

### 4c. webdav bytes_tx_ipv4_total accumulates on GET

**Scenario:** HTTP GET a file via `curl http://localhost:HTTP_WEBDAV_PORT/data/test.txt`.
Assert `xrootd_webdav_bytes_tx_ipv4_total` delta ≥ response size.

### 4d. webdav bytes_rx_ipv4_total accumulates on PUT (not +1 per request)

**Scenario:** PUT a 16 KB payload via `curl -T`. Assert `xrootd_webdav_bytes_rx_ipv4_total`
delta ≥ 16384. Assert delta is NOT 1 (which would expose the old count-not-bytes bug).

### 4e. s3 bytes_tx_ipv4_total accumulates on GetObject

**Scenario:** GET an S3 object via `boto3` or `curl`. Assert
`xrootd_s3_bytes_tx_ipv4_total` delta ≥ object size.

### 4f. s3 bytes_rx_ipv4_total accumulates on PutObject (not +1)

**Scenario:** PUT a 16 KB S3 object. Assert `xrootd_s3_bytes_rx_ipv4_total` delta ≥ 16384,
NOT equal to 1.

---

## 5. Prometheus metrics — WebDAV protocol layer

**File:** `tests/test_webdav_metrics.py` (new file)

### 5a. GET response increments webdav_requests_total{method="GET"}

**Scenario:** HTTP GET via `curl`. Assert `xrootd_webdav_requests_total{method="GET"}`
delta ≥ 1 and `xrootd_webdav_responses_total{method="GET", status="2xx"}` delta ≥ 1.

### 5b. PUT increments webdav_requests_total{method="PUT"} and bytes_rx_total

**Scenario:** HTTP PUT via `curl -T`. Assert request counter and `bytes_rx_total` delta.

### 5c. PROPFIND increments requests_total and bytes_tx_total

**What it verifies:** PROPFIND responses (directory listings) add to `bytes_tx_total`.
This was missing before the fix to `propfind.c`.

**Scenario:**
1. Baseline `xrootd_webdav_bytes_tx_total`.
2. `curl -X PROPFIND http://localhost:HTTP_WEBDAV_PORT/data/`.
3. Measure response body size.
4. Assert `bytes_tx_total` delta ≥ response size.

### 5d. PROPFIND bytes_tx_ipv4 also increments (not just bytes_tx_total)

Same test extended to assert `bytes_tx_ipv4_total` delta ≥ response size.

### 5e. DELETE increments webdav_requests_total{method="DELETE"}

### 5f. MKCOL increments webdav_requests_total{method="MKCOL"}

### 5g. 404 response increments responses_total{status="4xx"}

**Scenario:** GET a non-existent path. Assert `responses_total{method="GET", status="4xx"}`
delta ≥ 1.

### 5h. Auth counters — anonymous, cert, token

**Scenario:** Make one anonymous WebDAV request, one GSI request, one token request.
Assert `xrootd_webdav_auth_total{result="anonymous"}`, `{result="cert_ok"}`, and
`{result="token_ok"}` each increment by 1.

### 5i. Multipart-range GET bytes_tx_ipv4 accumulates

**What it verifies:** The `xrdhttp_multipart.c` bytes_tx_ipv tracking added in the fix.

**Scenario:** WebDAV GET with `Range: bytes=0-1023, 2048-3071` header (multi-range).
Assert `bytes_tx_ipv4_total` delta equals sum of both ranges.

### 5j. TPC push started and success counters

**Scenario:** Initiate a WebDAV COPY with `Source:` header (TPC pull). Assert
`xrootd_webdav_tpc_total{event="pull_started"}` and `{event="pull_success"}` each
increment.

### 5k. TPC bad-request counter on malformed TPC COPY

**Scenario:** COPY request missing `Source:` header. Assert
`xrootd_webdav_tpc_total{event="bad_request"}` increments.

---

## 6. Prometheus metrics — S3 protocol layer

**File:** `tests/test_s3_metrics.py` (new file)

### 6a. GetObject increments s3_requests_total{method="GET"}

**Scenario:** S3 GET via `curl` or `boto3`. Assert `xrootd_s3_requests_total{method="GET"}`
and `xrootd_s3_responses_total{method="GET", status="2xx"}` each increment.

### 6b. PutObject increments s3_requests_total{method="PUT"} and bytes_rx_total

### 6c. ListObjectsV2 increments requests_total{method="LIST"} and list_contents_total

**What it verifies:** `list_contents_total` was never incremented before the fix to
`list_objects_v2.c`. This test ensures it is now.

**Scenario:**
1. PUT three objects into a bucket.
2. Baseline `xrootd_s3_list_contents_total`.
3. S3 ListObjectsV2 the bucket.
4. Assert `list_contents_total` delta == 3.

### 6d. ListObjectsV2 with delimiter increments list_common_prefixes_total

**Scenario:** PUT `dir/a.txt`, `dir/b.txt`, `other.txt`. List with `delimiter=/`.
Assert `list_common_prefixes_total` delta == 1 (one `dir/` prefix).

### 6e. Paginated list increments list_truncated_total

**Scenario:** List a bucket with `max-keys=1` and more than one object. Assert
`list_truncated_total` delta == 1.

### 6f. PutObject bytes_rx_ipv4 accumulates (not request count)

**Scenario:** PUT a 32 KB object. Assert `xrootd_s3_bytes_rx_ipv4_total` delta ≥ 32768,
assert delta ≠ 1.

### 6g. GetObject bytes_tx_ipv4 accumulates

**Scenario:** GET a 32 KB object. Assert `xrootd_s3_bytes_tx_ipv4_total` delta ≥ 32768.

### 6h. Bad SigV4 signature increments auth_total{result="sig_mismatch"}

**Scenario:** S3 GET with a deliberately corrupted Authorization header. Assert
`xrootd_s3_auth_total{result="sig_mismatch"}` delta ≥ 1.

### 6i. DeleteObject increments s3_requests_total{method="DELETE"}

### 6j. 404 on missing key increments s3_responses_total{status="4xx"}

---

## 7. Prometheus metrics — token and auth counters

**File:** `tests/test_metrics.py` — add class `TestTokenCounters`

### 7a. Token server login increments op_ok{op="login"} on token port

**Scenario:** `xrdcp` with a valid WLCG bearer token to the token server (port 11097).
Assert `xrootd_requests_total{port=TOKEN_PORT, auth="token", op="login", status="ok"}`
delta ≥ 1.

### 7b. Expired token increments op_err on auth port

**Scenario:** Connect with an expired JWT. Assert `op_err{op="auth"}` increments.
The existing suite has no test for token auth failure reflected in the stream-layer
metrics.

### 7c. auth_total counters increment after GSI login

**Scenario:** `xrdcp` with a valid proxy. Assert `xrootd_auth_total` (the WebDAV
auth_total) is separate from the stream op counters. Verify the cert-ok path shows up.

---

## 8. Prometheus metrics — TPC and prepare ops

**File:** `tests/test_metrics.py` — add class `TestAdvancedOpCounters`

### 8a. kXR_prepare op_ok increments after a prepare request

**What it verifies:** The new `XROOTD_OP_PREPARE` constant and instrumentation added
to `query/prepare.c`.

**Scenario:**
1. Baseline `xrootd_requests_total{op="prepare", status="ok"}`.
2. Run `xrdfs root://localhost:ANON_PORT/ prepare /data/test.txt`.
3. Assert delta ≥ 1.

### 8b. kXR_prepare op_err increments on empty path list

**Scenario:** Send a raw kXR_prepare with an empty payload. Assert
`xrootd_requests_total{op="prepare", status="err"}` delta ≥ 1.

### 8c. query_stats op_ok increments after xrdfs spaceinfo

**Scenario:** `xrdfs root://localhost:ANON_PORT/ spaceinfo /`. Assert
`xrootd_requests_total{op="query_stats", status="ok"}` delta ≥ 1.

### 8d. query_xattr op_ok increments after xattr query

**Scenario:** `xrdfs root://localhost:ANON_PORT/ xattr /data/test.txt`. Assert
`xrootd_requests_total{op="query_xattr", status="ok"}` delta ≥ 1.

### 8e. locate op_ok increments after xrdfs locate

**Scenario:** `xrdfs root://localhost:ANON_PORT/ locate /data/test.txt`. Assert
`xrootd_requests_total{op="locate", status="ok"}` delta ≥ 1.

---

## 9. End-to-end: nginx redirector → xrootd data server

**File:** `tests/test_e2e_redirector_xrdcp.py` (new file)

This is the scenario the user identified as entirely absent: xrdcp connecting to nginx
running in CMS manager mode, nginx redirecting to a registered xrootd data server, and
xrdcp following that redirect to read or write an actual file. The existing
`test_manager_mode.py` tests verify the redirect _response_ at the wire level but no
test follows the redirect and performs an actual file transfer.

The fixture needed is the existing `cluster` fixture from `test_manager_mode.py` (nginx
manager + registered xrootd data server). Tests below use that fixture's
`redirector_port` and `dataserver_url`.

### 9a. xrdcp read through nginx redirector reaches xrootd data server

**What it verifies:** xrdcp can transparently follow a kXR_redirect from nginx to the
xrootd data server and read a file. The xrootd client's automatic redirect-following is
exercised in a real scenario.

**Scenario:**
1. Write a test file directly to the data server's filesystem root.
2. `xrdcp root://localhost:REDIRECTOR_PORT//test_file.bin /tmp/out.bin`.
3. Assert xrdcp returns 0.
4. Assert `/tmp/out.bin` contents match the file written in step 1.

**Assertions:**
```python
assert rc == 0
assert hashlib.md5(downloaded).hexdigest() == hashlib.md5(payload).hexdigest()
```

### 9b. xrdcp write through nginx redirector stores file on xrootd data server

**What it verifies:** xrdcp PUT is redirected to the data server and the file appears
in the data server's filesystem.

**Scenario:**
1. `xrdcp /tmp/upload.bin root://localhost:REDIRECTOR_PORT//uploads/upload.bin`.
2. Assert xrdcp returns 0.
3. Assert the file exists on the data server's local filesystem at the expected path.

### 9c. Large file (200 MB) round-trip through redirector preserves integrity

**What it verifies:** A 200 MB transfer through the redirect chain completes without
corruption.

**Scenario:**
1. Write `/tmp/xrd-test/data/large200.bin` to the data server.
2. `xrdcp root://localhost:REDIRECTOR_PORT//large200.bin /tmp/large_out.bin`.
3. Assert MD5 matches the known hash (stored in env var `LARGE200_MD5` by conftest).

### 9d. xrdfs stat through redirector returns correct file metadata

**What it verifies:** kXR_stat is redirected and the response propagates back through
nginx to the client with correct size and modification time.

**Scenario:**
```python
result = subprocess.run(
    ["xrdfs", f"root://localhost:{REDIRECTOR_PORT}", "stat", "/data/test.txt"],
    capture_output=True, text=True
)
assert result.returncode == 0
# xrdfs stat output contains "Size: N"
assert "Size:" in result.stdout
```

### 9e. xrdfs ls through redirector lists correct directory contents

**What it verifies:** kXR_dirlist redirected to data server returns accurate listing.

**Scenario:** Write 3 files to data server. `xrdfs ls` via redirector. Assert all 3
names appear.

### 9f. Parallel xrdcp downloads through redirector all succeed

**What it verifies:** Multiple simultaneous clients being redirected from the same
nginx manager instance each complete without corruption or dropped connections.

**Scenario:**
1. Launch 5 `subprocess.Popen` xrdcp processes simultaneously, all reading the same
   test file through the redirector.
2. Wait for all to complete (timeout 30s).
3. Assert all 5 return code == 0.
4. Assert all 5 output files have the same MD5.

### 9g. xrdcp read with GSI auth through redirector

**What it verifies:** Authenticated xrdcp (GSI proxy) is redirected correctly and auth
context is preserved.

**Scenario:** Same as 9a but using `root://` against the GSI-auth redirector port with
`X509_USER_PROXY` set.

### 9h. Redirector metrics update after client file transfer

**What it verifies:** Transfers that go through the redirect (data served by xrootd,
not nginx) still count in nginx's redirector-side metrics (connections, logins).

**Scenario:**
1. Baseline `xrootd_connections_total` and `op_ok{op="login"}` on the redirector port.
2. Run `xrdcp` through the redirector.
3. Assert both counters increment — the redirect handshake counts even though data
   bytes flow via the data server.

### 9i. xrdcp TPC through nginx redirector

**What it verifies:** A third-party copy where the source URL goes through the nginx
redirector. xrdcp contacts nginx, gets redirected to the xrootd data server, reads
from there, and writes to a different destination.

**Scenario:**
```bash
xrdcp root://localhost:REDIRECTOR_PORT//src.bin \
      root://localhost:ANON_PORT//dst.bin
```
Assert dst.bin contents match src.bin.

---

## 10. End-to-end: high-level WebDAV round-trip

**File:** `tests/test_a_webdav_clients.py` — add to existing module

The existing tests cover xrdcp davs:// upload/download. The following are missing:

### 10a. xrdcp davs:// read back verifies byte-exact contents (not just success)

**What it verifies:** The existing `test_xrdcp_upload_and_download` checks xrdcp
returns 0 but does not compare file hashes. Byte corruption would go undetected.

**Assertions:** `assert md5(downloaded) == md5(original_payload)`.

### 10b. curl PUT then xrdcp GET cross-client round-trip

**What it verifies:** A file uploaded via HTTP PUT (curl) can be downloaded by
xrdcp using the davs:// protocol, exercising the WebDAV ↔ XRootD namespace sharing.

**Scenario:**
1. `curl -T /tmp/source.bin http://localhost:HTTP_WEBDAV_PORT/data/cross_test.bin`.
2. `xrdcp davs://localhost:WEBDAV_PORT//data/cross_test.bin /tmp/result.bin`.
3. Assert hash matches.

### 10c. WebDAV PROPFIND depth-1 returns correct file count

**Scenario:** PUT 3 files in a directory, PROPFIND depth=1 that directory. Parse XML
response, count `<D:response>` elements. Assert count == 4 (directory + 3 files).

### 10d. WebDAV COPY (server-side) preserves byte content

**Scenario:** PUT a file. COPY it to a new path. GET the copy. Assert hash matches
original.

### 10e. WebDAV DELETE removes file and subsequent GET returns 404

---

## 11. End-to-end: high-level S3 round-trip

**File:** `tests/test_s3.py` — extend or `tests/test_s3_e2e.py` (new)

### 11a. PutObject then GetObject byte-exact round-trip

**What it verifies:** The S3 PUT → GET path preserves exact bytes (no corruption from
staging or encoding).

**Scenario:**
```python
payload = os.urandom(65536)
client.put_object(Bucket="bucket", Key="round_trip.bin", Body=payload)
resp = client.get_object(Bucket="bucket", Key="round_trip.bin")
assert resp["Body"].read() == payload
```

### 11b. Multipart upload then GetObject byte-exact round-trip

**What it verifies:** The multipart upload path (InitiateMultipartUpload → UploadPart
× N → CompleteMultipartUpload) produces a correct object.

**Scenario:** Upload a 15 MB object in three 5 MB parts. GetObject. Assert MD5 matches.

### 11c. ListObjectsV2 returns correct key names and sizes

**Scenario:** PUT objects with specific names and sizes. ListObjectsV2. Assert each
expected key appears with correct `Size` field.

### 11d. HeadObject returns correct Content-Length and Last-Modified

### 11e. DeleteObject removes object (subsequent HeadObject → 404)

### 11f. CopyObject preserves content

**What it verifies:** S3 server-side copy produces identical bytes.

### 11g. Presigned URL GET works without AWS credentials in request

**Scenario:** Generate a presigned GET URL via `generate_presigned_url`. Download with
`requests.get()` (no auth headers). Assert 200 and correct content.

---

## 12. End-to-end: large file integrity and metrics

**File:** `tests/test_large_file_metrics.py` (new file)

### 12a. 200 MB xrdcp download byte-exact and metrics agree

**What it verifies:** A full 200 MB transfer completes correctly and the bytes_tx_total
metric delta is within 5% of 200 MB (not 0, not 10x).

**Scenario:**
1. Baseline `xrootd_bytes_tx_total{port=ANON_PORT}`.
2. `xrdcp root://localhost:ANON_PORT//large200.bin /tmp/large_out.bin`.
3. Assert xrdcp returns 0.
4. Assert `/tmp/large_out.bin` MD5 matches known hash.
5. `delta = bytes_tx_after - bytes_tx_before`
6. Assert `200 * 1024 * 1024 <= delta <= 220 * 1024 * 1024`.

### 12b. 200 MB xrdcp upload byte-exact

**Scenario:** Upload `/tmp/xrd-test/data/large200.bin` (200 MB). Assert xrdcp returns
0. Assert file exists in data dir with correct size. Assert `bytes_rx_total` delta is
within 5% of 200 MB.

### 12c. Large WebDAV PUT then GET byte-exact

**Scenario:** `curl -T large200.bin http://...`, then `curl -o out.bin http://...`.
Assert MD5 matches.

### 12d. Large S3 PutObject byte-exact

**Scenario:** `boto3.upload_file` for a 200 MB file. GetObject, assert MD5.

### 12e. CRC32c checksum after large download matches server-computed value

**What it verifies:** nginx correctly computes CRC32c for a file and returns the same
value the reference xrootd server would return, and this matches an independently
computed local CRC32c.

**Scenario:**
1. Compute local CRC32c of `/tmp/xrd-test/data/large200.bin` with the `crc32c` library.
2. `xrdfs root://localhost:ANON_PORT/ query checksum /large200.bin`.
3. Parse the `crc32c:XXXXXXXX` response.
4. Assert values match.

---

## Coverage summary

| Area | Currently tested | Key gaps |
|------|-----------------|----------|
| Stream op names | 17 of 38 ops | query_space, readv, pgread, …, prepare |
| Stream op_err | 0 tests | login err, stat err, open_wr err |
| bytes count accuracy | ≥ N only | upper bound; large file |
| Per-IP-version bytes | 0 tests | ipv4/ipv6 for all three protocols |
| WebDAV metrics | 0 dedicated tests | all method counters, PROPFIND bytes |
| S3 metrics | 0 dedicated tests | list_contents, per-method, auth counters |
| Token metrics | 0 stream tests | op_ok/err on token port |
| prepare op | 0 tests | op_ok and op_err |
| nginx-redir → xrootd | 0 xrdcp e2e | read, write, large, parallel, GSI, TPC |
| WebDAV e2e | partial | byte-exact hash, cross-client, PROPFIND depth |
| S3 e2e | partial | multipart integrity, CopyObject, byte-exact |
| Large file + metrics | 0 tests | bytes delta bound for 200 MB |
