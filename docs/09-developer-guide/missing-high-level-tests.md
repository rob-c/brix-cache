# Missing High-Level Functionality Tests

## Overview

This document identifies high-level functional tests that should logically exist but are not currently present in the test suite. These focus on end-to-end scenarios combining multiple subsystems — Prometheus metrics validation through actual xrdcp copy operations, cross-protocol integration, full-stack TLS + auth + data transfer, and operational monitoring patterns that real HEP sites exercise daily.

The existing test suite has 90+ files covering individual opcodes, protocol conformance, auth mechanisms, and per-protocol metric counters. What's missing is **integration-level tests** that validate the system works as a whole when multiple subsystems interact.

---

## Current Metrics Coverage (What Exists)

### `tests/test_metrics.py`
Tests Prometheus `/metrics` endpoint for:
- Anon/GSI/op labels counters (`brix_requests_total`)
- Error counters (`brix_errors_total`)
- Byte counters per protocol (`brix_bytes_sent_total`, `brix_bytes_recv_total`)
- IP version tracking
- Token auth counters

### `tests/test_webdav_metrics.py`
Tests WebDAV-specific metrics: request counters, auth counters, multipart TPC counters.

### `tests/test_s3_metrics.py`
Tests S3-specific metrics: request counters, list counters, IP version bytes, auth counters.

### `tests/test_large_file_metrics.py`
Tests large file transfer metrics tracking (12 standalone functions).

---

## What the Monitoring Guide Expects (from docs/08-metrics-monitoring/monitoring-guide.md)

The monitoring guide documents these expected Prometheus metric families:

| Metric Family | Description | PromQL Examples in Guide |
|---------------|-------------|-------------------------|
| `brix_requests_total` | Per-op counters by protocol + status | `sum by (op, proto) (rate(brix_requests_total[5m]))` |
| `brix_bytes_sent_total` / `brix_bytes_recv_total` | Byte counters per protocol | `irate(brix_bytes_sent_total[1m])` for throughput |
| `brix_auth_total` | Auth events by method + result | `sum by (method, result) (rate(brix_auth_total[5m]))` |
| `brix_errors_total` | Errors by errno family | `sum by (errno) (rate(brix_errors_total[5m]))` |
| `brix_fd_cache_hits_total` / `misses_total` | FD cache hit/miss ratio | `fd_cache_hits_total / (fd_cache_hits_total + fd_cache_misses_total)` |
| `brix_tpc_transfers_total` | TPC transfers by mode | `sum by (mode) (rate(brix_tpc_transfers_total[5m]))` |
| `brix_cache_hits_total` / `misses_total` | Read-through cache hit/miss | Cache fill rate analysis |
| `brix_write_through_syncs_total` | Write-through mirroring events | Sync success/failure rates |
| `brix_cms_heartbeat_total` | CMS heartbeat ping events | Heartbeat interval monitoring |
| `brix_session_bind_total` / `unbind_total` | Session lifecycle events | Active session count tracking |

---

## Missing Tests (Categorized by Gap Type)

### Category 1: End-to-End xrdcp Through Nginx Redirect + Metrics Validation

These tests exercise the full stack from client → nginx redirect → xrootd backend, then validate Prometheus metrics reflect the actual operations performed.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 1 | `test_e2e_xrdcp_metrics_validation` | Run xrdcp read/write through nginx redirect port → scrape `/metrics` → verify counters incremented by exact amounts (bytes_sent = file size, requests_total[op="read"] += N) | Only `test_large_file_metrics.py` tests metrics with Python client; no test uses real xrdcp binary + nginx redirect + metric validation together |
| 2 | `test_e2e_xrdcp_auth_metrics_validation` | Run xrdcp login (anon → GSI → token) through nginx redirect → scrape `/metrics` → verify `brix_auth_total{method="gsi",result="ok"}` increments, then read operation → verify bytes counters match | Auth metrics tested per-protocol but not validated against actual auth events from real xrdcp client |
| 3 | `test_e2e_xrdcp_parallel_metrics_validation` | Run parallel xrdcp copies (N files) through nginx redirect → scrape `/metrics` → verify `requests_total` = N × operations, bytes counters sum correctly across concurrent sessions | Concurrent tests exist (`test_concurrent.py`) but no test validates metrics under concurrency pressure |
| 4 | `test_e2e_xrdcp_error_metrics_validation` | Run xrdcp against non-existent path / unauthorized path → scrape `/metrics` → verify `brix_errors_total{errno="ENOENT"}` and `brix_requests_total{status="error"}` increment correctly | Error counters tested individually but not validated end-to-end with real client errors |
| 5 | `test_e2e_xrdcp_proxy_mode_metrics_validation` | Run xrdcp through nginx transparent proxy mode → backend xrootd → scrape `/metrics` → verify metrics show nginx as the observed layer, backend identity hidden, counters still increment correctly | Proxy mode tested (`test_proxy_mode.py`) but no test validates metrics in proxy mode specifically |

### Category 2: Cross-Protocol Metrics Consistency

These tests validate that a single operation performed via multiple protocols produces consistent metric increments across all protocol families.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 6 | `test_cross_protocol_metrics_consistency` | Upload same file via root:// and davs:// → scrape `/metrics` → verify `brix_bytes_sent_total{proto="root"}` + `brix_bytes_sent_total{proto="dav"}` = 2 × file_size, request counters match per protocol | Metrics tested per-protocol but never validated that cross-protocol operations produce consistent totals |
| 7 | `test_cross_protocol_auth_metrics_consistency` | Authenticate via GSI on root:// port and davs:// port with same proxy cert → scrape `/metrics` → verify `brix_auth_total{method="gsi",result="ok"}` counts both sessions, no double-counting | Auth metrics exist but cross-protocol auth consistency not validated |
| 8 | `test_cross_protocol_error_metrics_consistency` | Same path error (ENOENT) via root:// and davs:// → scrape `/metrics` → verify error counters increment per protocol independently, total errors = sum across protocols | Error metrics tested individually but cross-protocol aggregation not verified |

### Category 3: Full-Stack TLS + Auth + Data Transfer Lifecycle

These tests validate complete request lifecycles from TLS handshake through auth to data transfer and metrics emission.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 9 | `test_full_stack_tls_gsi_lifecycle` | roots:// connection → TLS handshake → GSI login with proxy cert → stat → read file → close → scrape `/metrics` → verify entire lifecycle: auth_total{method="gsi",result="ok"} = 1, requests_total[op="stat"] = 1, requests_total[op="read"] = 1, bytes_sent = file_size | GSI TLS tested (`test_gsi_tls.py`) but no test validates complete lifecycle with metrics at each stage |
| 10 | `test_full_stack_tls_token_lifecycle` | roots:// connection → TLS handshake → WLCG JWT bearer token login → scope-enforced read/write → scrape `/metrics` → verify auth_total{method="token",result="ok"} = 1, requests scoped correctly, bytes counters match | Token auth tested (`test_token_auth.py`) but no test validates complete lifecycle with metrics |
| 11 | `test_full_stack_tls_failed_auth_lifecycle` | roots:// connection → TLS handshake → invalid GSI cert / expired token → scrape `/metrics` → verify auth_total{method="gsi",result="failed"} or auth_total{method="token",result="invalid"} increments, no bytes counters increment (no data transferred) | Auth failure tested but not validated end-to-end with metrics showing zero bytes for failed sessions |

### Category 4: TPC End-to-End + Cross-Protocol Metrics

These tests validate native and WebDAV TPC transfers through the full stack with metric validation.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 12 | `test_e2e_native_tpc_metrics` | Native TPC: xrdcp copyprocess from source → destination via SHM key registry → scrape `/metrics` → verify `brix_tpc_transfers_total{mode="native"}` increments, bytes counters on both source and destination servers match | Native TPC tested (`test_root_tpc.py`) but no test validates metrics on both sides of the transfer |
| 13 | `test_e2e_webdav_tpc_metrics` | WebDAV HTTP-TPC: curl COPY with Source/Credential headers → scrape `/metrics` → verify `brix_tpc_transfers_total{mode="webdav"}` increments, bytes counters on source/destination match, TPC-specific counters increment | WebDAV TPC tested (`test_webdav_tpc.py`) but no test validates metrics across the HTTP-TPC transfer |
| 14 | `test_e2e_cross_protocol_tpc` | TPC from root:// source to davs:// destination (or vice versa) → scrape `/metrics` on both servers → verify cross-protocol metric labels, bytes transferred consistent on both sides | No test exercises TPC across protocol boundaries (root:// ↔ davs://) |

### Category 5: Cache Metrics + End-to-End Validation

These tests validate read-through cache hit/miss ratios and write-through mirroring events in Prometheus metrics.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 15 | `test_e2e_cache_hit_metrics_validation` | Configure nginx read-through cache → xrdcp read same file N times through redirect → scrape `/metrics` → verify first request = cache miss, subsequent requests = cache hits, `brix_cache_hits_total` / `brix_cache_misses_total` ratio matches expected pattern | Cache tested (`test_http_cache_hit.py`) but no test validates cache hit/miss metrics over multiple accesses |
| 16 | `test_e2e_write_through_metrics_validation` | Configure write-through mirroring → xrdcp write file through nginx redirect to origin → scrape `/metrics` → verify `brix_write_through_syncs_total` increments, bytes_sent on both cache server and origin match, sync success/failure counters accurate | Write-through tested (`test_cache_write_through.py`) but no test validates metrics during write-through operations |
| 17 | `test_e2e_cache_eviction_metrics` | Fill cache → evict entries (via config reload or TTL expiry) → scrape `/metrics` → verify cache hit ratio drops after eviction, new accesses = misses, total hits/misses reset appropriately | Cache lifecycle tested but no test validates metrics during cache eviction events |

### Category 6: CMS / Manager Mode + Metrics Validation

These tests validate CMS heartbeat, cluster registry, and multi-tier topology metrics.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 18 | `test_e2e_cms_heartbeat_metrics` | Start manager mode with multiple servers → scrape `/metrics` → verify `brix_cms_heartbeat_total{server="X"}` increments per heartbeat interval, server registry count matches active servers, locate responses counted correctly | CMS tested (`test_cms.py`) but no test validates CMS-specific metrics over time |
| 19 | `test_e2e_manager_cluster_metrics` | Multi-tier manager topology (3 tiers) → scrape `/metrics` → verify per-server counters, cluster-wide totals, redirect events counted correctly, server registration/unregistration tracked in metrics | Manager mode tested (`test_manager_mode.py`) but no test validates cluster-level metrics aggregation |
| 20 | `test_e2e_cms_reconnect_metrics` | CMS server disconnects and reconnects → scrape `/metrics` → verify unbind_total increments on disconnect, bind_total increments on reconnect, session counters reflect active sessions correctly after reconnection | CMS reconnect tested but no test validates metrics during reconnect events |

### Category 7: Session Lifecycle + Metrics Validation

These tests validate session bind/unbind events, handle lifecycle, and FD cache behavior reflected in Prometheus metrics.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 21 | `test_e2e_session_bind_metrics` | Multiple concurrent xrdcp sessions → scrape `/metrics` → verify `brix_session_bind_total` = N active sessions, `brix_session_unbind_total` = closed sessions, fd_cache_hits/misses correlate with session count | Session bind tested (`test_session_bind.py`) but no test validates session lifecycle metrics under concurrency |
| 22 | `test_e2e_fd_cache_metrics_validation` | Open same file via multiple sessions → scrape `/metrics` → verify `brix_fd_cache_hits_total` increments for reused handles, `fd_cache_misses_total` for new opens, cache hit ratio = reused_handles / total_opens | FD cache tested in proxy mode but no standalone test validates fd_cache metrics directly |
| 23 | `test_e2e_handle_lifecycle_metrics` | Open → read → stat (same handle) → close → open again → scrape `/metrics` → verify requests_total[op="read"] and [op="stat"] counted on same session, close increments unbind or session counter appropriately | Handle lifecycle tested in individual opcode tests but not validated as complete lifecycle with metrics |

### Category 8: Throughput + Latency Metrics End-to-End

These tests validate throughput and latency metric tracking during large file transfers.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 24 | `test_e2e_throughput_metrics_validation` | xrdcp copy large file (100MB+) through nginx redirect → scrape `/metrics` during transfer → verify `irate(brix_bytes_sent_total[1m])` matches actual throughput, requests_total[op="read"] = page_count, pgread counters match | Throughput tested (`test_throughput.py`) with 200MB streaming but no test validates metrics during the transfer in real-time |
| 25 | `test_e2e_latency_metrics_validation` | Run stat/dirlist/locate/query/read operations through nginx redirect → scrape `/metrics` → verify latency counters (if defined) or derive from request timing + counter increments, compare against reference xrootd latency | Latency tested in performance conformance (`test_brix_performance_conformance.py`) but no test validates latency reflected in metrics |
| 26 | `test_e2e_chunked_read_metrics` | xrdcp chunked read (multiple reads with gaps) through nginx redirect → scrape `/metrics` → verify each read increments requests_total[op="read"] independently, bytes_sent = sum of all chunks, no duplicate counting for overlapping ranges | Chunked reads tested in throughput but metrics per-chunk validation not present |

### Category 9: Dashboard API + Metrics Cross-Validation

These tests validate the HTTPS dashboard API (`/brix/api/v1/`) against actual Prometheus metric values.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 27 | `test_e2e_dashboard_api_metrics_cross_validation` | Run operations through nginx → scrape `/metrics` AND scrape `/brix/api/v1/snapshot` → verify dashboard JSON values match Prometheus counter values (transfers count, auth events, bytes transferred) | Dashboard API tested (`test_dashboard.py`) for schema correctness but no test cross-validates against actual Prometheus counters |
| 28 | `test_e2e_dashboard_api_realtime_update` | Run operations through nginx → scrape `/brix/api/v1/snapshot` before and after → verify snapshot values increment correctly (active transfers count, auth event counts, bytes transferred) | Dashboard tested for static schema but no test validates realtime updates during active operations |

### Category 10: Metrics Label Cardinality + Scale Validation

These tests validate that metric labels remain low-cardinality under scale (no path/bucket/UUID label explosion).

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 29 | `test_metrics_label_cardinality_at_scale` | Run 1000+ operations with unique paths → scrape `/metrics` → verify number of distinct label combinations stays bounded (proto, op, status, method — no path labels), total time series count < threshold | Metrics tested for basic correctness but no test validates cardinality under scale |
| 30 | `test_metrics_persistence_across_restart` | Run operations → scrape metrics → restart nginx server → run more operations → scrape metrics again → verify counters persist (not reset to zero) or increment correctly after restart | No test validates metric persistence across server lifecycle events |

### Category 11: Cross-Backend Metrics Conformance

These tests validate that BriX-Cache Prometheus metrics match reference xrootd daemon metrics for equivalent operations.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 31 | `test_cross_backend_metrics_conformance` | Run same operations against both BriX-Cache and reference xrootd → scrape `/metrics` from both → verify counter names, label structure, increment patterns match (nginx may have additional labels but base counters should align) | Cross-backend conformance exists for opcodes (`TEST_CROSS_BACKEND`) but no test compares Prometheus metrics between backends |
| 32 | `test_cross_backend_webdav_metrics_conformance` | Run WebDAV operations against both BriX-Cache and reference XrdHttp → scrape `/metrics` from both → verify webdav-specific counters match in structure and increment behavior | No cross-backend conformance test for WebDAV metrics (XrdHttp conformance tests exist but only for HTTP methods, not metrics) |

### Category 12: S3 Multipart + Lifecycle Metrics

These tests validate S3 multipart upload lifecycle metrics end-to-end.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 33 | `test_e2e_s3_multipart_metrics_validation` | S3 multipart upload (N parts) via nginx → scrape `/metrics` → verify request counters per part, total bytes_sent = sum of all parts + completion, multipart-specific counters increment correctly, abort events counted if aborted | S3 multipart tested (`test_s3_multipart.py`) but no test validates metrics during multipart lifecycle |
| 34 | `test_e2e_s3_presigned_metrics_validation` | Generate presigned URL → xrdcp/aws s3 cp via presigned URL → scrape `/metrics` → verify auth_total{method="presigned"} increments, bytes counters match, expiration events tracked if expired URL used | S3 presigned tested (`test_s3_presigned.py`) but no test validates metrics for presigned URL operations |

### Category 13: WebDAV Proxy + End-to-End Metrics

These tests validate WebDAV perimeter proxy mode with metric validation.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 35 | `test_e2e_webdav_proxy_metrics_validation` | HTTPS client → nginx WebDAV proxy → HTTP backend DAV server → scrape `/metrics` on nginx → verify webdav_bytes_sent_total, auth counters increment, proxy-specific counters if defined (upstream requests, backend latency) | WebDAV proxy tested but no test validates metrics in proxy mode specifically |
| 36 | `test_e2e_webdav_proxy_auth_metrics_validation` | WLCG token auth at nginx perimeter → forward to HTTP backend without auth → scrape `/metrics` → verify auth_total{method="token",result="ok"} counted at nginx, bytes counters match, backend sees no auth events (nginx terminates auth) | WebDAV proxy auth tested but no test validates metrics showing auth termination at nginx layer |

### Category 14: ACL + VO Metrics Validation

These tests validate access control and VO-specific metrics.

| # | Test Name | What It Tests | Why Missing? |
|---|-----------|---------------|--------------|
| 37 | `test_e2e_vo_acl_metrics_validation` | Atlas proxy cert → stat/read/write on Atlas paths, CMS proxy cert → same paths → scrape `/metrics` → verify auth_total{method="gsi",result="ok"} per VO, access denied counters for cross-VO operations (Atlas reading CMS-only path) | VO ACL tested (`test_vo_acl.py`) but no test validates metrics during VO-specific access control |
| 38 | `test_e2e_authdb_metrics_validation` | AuthDB public/private paths → xrdcp read both types → scrape `/metrics` → verify auth_total increments for private path auth, anon counters for public path reads, error counters for unauthorized private path access | AuthDB tested (`test_authdb.py`) but no test validates metrics during authDB-gated operations |

---

## Priority Ranking (Recommended Implementation Order)

| Priority | Tests | Rationale |
|----------|-------|-----------|
| **P1 — Critical** | #1, #2, #9, #10 | Core e2e scenarios every HEP site exercises: xrdcp through nginx redirect with metrics, full-stack TLS+auth+data. These are the "smoke tests" for production deployment. |
| **P2 — High** | #3, #4, #6, #7, #15, #18 | Concurrency, errors, cross-protocol consistency, cache hit/miss, CMS heartbeat. These validate operational reliability under real conditions. |
| **P3 — Medium** | #12, #13, #24, #27, #29 | TPC metrics, throughput validation, dashboard cross-validation, label cardinality. These are important for production-scale deployment but not day-one critical. |
| **P4 — Low** | #16, #17, #20, #31, #33, #35 | Write-through cache eviction, multi-tier manager, cross-backend conformance, S3 multipart lifecycle, WebDAV proxy metrics. These are niche scenarios or advanced features. |

---

## Test Pattern (Per AGENTS.md: 3 tests per feature)

Each missing test should follow the standard pattern of **success + error + security-negative**:

| Variant | Description | Example |
|---------|-------------|---------|
| **Success** | Normal operation through full stack, metrics validate correctly | xrdcp read file → metrics show bytes_sent = file_size |
| **Error** | Operation fails (ENOENT, EACCES) → metrics show error counters increment, no data counters | xrdcp read non-existent path → errors_total{errno="ENOENT"} = 1 |
| **Security-Neg** | Unauthorized operation (wrong cert, expired token, scope mismatch) → auth shows failed, bytes = 0 | xrdcp with expired token → auth_total{method="token",result="invalid"} = 1 |

---

## Implementation Notes

### Required Infrastructure
- All tests require `tests/manage_test_servers.sh start` (nginx + ref xrootd servers running)
- Metrics endpoint accessible at port 9100 (`/metrics`)
- Dashboard API accessible at configured dashboard port (`/brix/api/v1/snapshot`)
- xrdcp binary available on test system path

### Helper Functions Needed
Each e2e test will need:
1. `run_xrdcp_command(protocol, port, src, dst)` — execute xrdcp and capture exit code + stderr
2. `scrape_metrics(port=9100)` — HTTP GET `/metrics` and parse Prometheus text format
3. `parse_metric_value(metric_name, labels)` — extract counter value from scraped metrics
4. `verify_metric_increment(expected_delta, actual_delta)` — assert counters match expected values

### Cross-Backend Pattern
Tests #31/#32 should follow existing `TEST_CROSS_BACKEND` pattern:
```python
pytest tests/test_cross_backend_metrics.py -v TEST_CROSS_BACKEND=nginx
pytest tests/test_cross_backend_metrics.py -v TEST_CROSS_BACKEND=xrootd
```

---

## File Inventory Summary (Existing + Proposed)

### Existing Metrics Tests
| File | Coverage |
|------|----------|
| `tests/test_metrics.py` | Basic counter validation per protocol |
| `tests/test_webdav_metrics.py` | WebDAV-specific counters |
| `tests/test_s3_metrics.py` | S3-specific counters |
| `tests/test_large_file_metrics.py` | Large file transfer metrics (12 functions) |

### Existing E2E Tests
| File | Coverage |
|------|----------|
| `tests/test_e2e_redirector_xrdcp.py` | xrdcp through redirector (read/write/stat/ls/parallel/cross-server) — NO metric validation |
| `tests/test_a_webdav_clients.py` | WebDAV E2E cross-client round-trip — NO metric validation |
| `tests/test_gsi_bridge.py` | GSI bridge transfers — NO metric validation |

### Proposed New Tests (38 tests, grouped into ~15 files)
| File | Tests Included |
|------|----------------|
| `test_e2e_xrdcp_metrics.py` | #1, #2, #3, #4, #5 |
| `test_cross_protocol_metrics.py` | #6, #7, #8 |
| `test_full_stack_lifecycle.py` | #9, #10, #11 |
| `test_tpc_metrics.py` | #12, #13, #14 |
| `test_cache_metrics.py` | #15, #16, #17 |
| `test_cms_metrics.py` | #18, #19, #20 |
| `test_session_metrics.py` | #21, #22, #23 |
| `test_throughput_latency_metrics.py` | #24, #25, #26 |
| `test_dashboard_cross_validation.py` | #27, #28 |
| `test_metrics_cardinality.py` | #29, #30 |
| `test_cross_backend_metrics.py` | #31, #32 |
| `test_s3_lifecycle_metrics.py` | #33, #34 |
| `test_webdav_proxy_metrics.py` | #35, #36 |
| `test_vo_acl_metrics.py` | #37, #38 |

---

## Cross-References

- Existing metrics tests: `tests/test_metrics.py`, `tests/test_webdav_metrics.py`, `tests/test_s3_metrics.py`
- Monitoring guide (expected metric families): `docs/08-metrics-monitoring/monitoring-guide.md`
- Dashboard API schema: `tests/test_dashboard.py`
- E2e redirector xrdcp (existing, no metrics): `tests/test_e2e_redirector_xrdcp.py`
- Testing runbook (3-test pattern): `docs/09-developer-guide/testing-runbook.md`
- Metrics enum definitions: `src/observability/metrics/metrics.h`

---

*Last updated: 2026-05-27 — Audit of missing high-level functionality tests.*
