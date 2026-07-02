# Dual-Stack Transfer Test Plan

## Purpose

Add behavioral coverage that proves nginx-xrootd can complete real transfers
over:

- IPv4-only paths.
- IPv6-only paths.
- Mixed IPv4/IPv6 paths where the data-transfer family is selected by the
  first XRootD response the client receives, such as `kXR_redirect` or
  `kXR_locate`.

This plan focuses on the stream `root://` module because it owns native XRootD
socket handling, redirect formatting, bind handling, proxy mode, cache origin
connects, and native TPC. WebDAV and S3 mostly rely on nginx HTTP socket
machinery and should only be included here where they trigger module-owned
outbound transfer code.

## Non-Goals

- Do not test resolver ordering by relying on `localhost`; libc and CI images
  differ. Use literal `127.0.0.1` and `[::1]` for deterministic tests.
- Do not require editing `/etc/hosts`.
- Do not create ad hoc nginx/xrootd instances from individual tests. The current
  test harness expects suite-level dedicated roles with fixed ports.
- Do not use path or hostname values as metric labels. Assertions should consume
  existing low-cardinality metrics and access logs.

## Preconditions

The suite should skip this module cleanly when:

- The host kernel has no IPv6 loopback support.
- `socket.create_connection(("::1", port))` cannot be used locally.
- `xrdcp` or `xrdfs` is missing.
- nginx was built without stream support.

Add a helper such as `require_ipv6_loopback()` that:

1. Creates an `AF_INET6` listener on `[::1]:0`.
2. Connects to it from `[::1]`.
3. Skips the test module if either step fails.

## Test Infrastructure Changes

### New test module

Create `tests/test_dual_stack_transfers.py`.

Core helpers:

- `run_xrdcp(args, timeout=120)`: wraps `xrdcp -s` with proxy and auth
  environment variables removed.
- `sha256(path)`: verifies transferred bytes.
- `write_pattern(path, size)`: creates deterministic payloads.
- `read_metrics()`: fetches `/metrics` from the existing metrics endpoint.
- `metric_value(name, labels)`: parses Prometheus text for a single metric.
- `access_log_tail(role)`: returns the last lines for a dedicated server.
- `xrd_session(family, host, port)`: wire-level handshake/login helper for
  `kXR_locate` and redirect probes.
- `parse_redirect(body)`: returns `(host, port)` from `kXR_redirect`.
- `parse_locate(body)`: returns advertised locate entries.

### New fixed settings

Add fixed ports to `tests/settings.py`, using the next free block after the
existing dedicated servers:

```python
DUALSTACK_V4_PORT = int(os.environ.get("TEST_DUALSTACK_V4_PORT", "11230"))
DUALSTACK_V6_PORT = int(os.environ.get("TEST_DUALSTACK_V6_PORT", "11231"))
DUALSTACK_MANAGER_V4_PORT = int(os.environ.get("TEST_DUALSTACK_MANAGER_V4_PORT", "11232"))
DUALSTACK_MANAGER_V6_PORT = int(os.environ.get("TEST_DUALSTACK_MANAGER_V6_PORT", "11233"))
DUALSTACK_DS_V4_PORT = int(os.environ.get("TEST_DUALSTACK_DS_V4_PORT", "11234"))
DUALSTACK_DS_V6_PORT = int(os.environ.get("TEST_DUALSTACK_DS_V6_PORT", "11235"))
DUALSTACK_PROXY_PORT = int(os.environ.get("TEST_DUALSTACK_PROXY_PORT", "11236"))
DUALSTACK_CACHE_PORT = int(os.environ.get("TEST_DUALSTACK_CACHE_PORT", "11237"))
DUALSTACK_TPC_SRC_PORT = int(os.environ.get("TEST_DUALSTACK_TPC_SRC_PORT", "11238"))
DUALSTACK_TPC_DST_PORT = int(os.environ.get("TEST_DUALSTACK_TPC_DST_PORT", "11239"))
DUALSTACK_CMS_PORT = int(os.environ.get("TEST_DUALSTACK_CMS_PORT", "12630"))
```

Register those ports in `tests/manage_test_servers.sh force-stop` so failed
runs do not leave listeners behind.

### New dedicated config templates

Add these templates under `tests/configs/`.

`nginx_dualstack_v4.conf`:

```nginx
stream {
    server {
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_access_log {LOG_DIR}/xrootd_access.log;
    }
}
```

`nginx_dualstack_v6.conf`:

```nginx
stream {
    server {
        listen [::1]:{PORT} ipv6only=on;
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_access_log {LOG_DIR}/xrootd_access.log;
    }
}
```

`nginx_dualstack_ds_v4.conf` and `nginx_dualstack_ds_v6.conf`:

- Same as direct server templates.
- Include `xrootd_cms_manager {CMS_HOST}:{CMS_PORT};`.
- Include `xrootd_cms_paths /;`.
- Include `xrootd_listen_port {PORT};`.
- Use `CMS_HOST=127.0.0.1` for the IPv4 data server and `CMS_HOST=[::1]` for
  the IPv6 data server after CMS address parsing supports brackets.

`nginx_dualstack_manager.conf`:

```nginx
stream {
    server {
        listen 127.0.0.1:{MANAGER_V4_PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_manager on;
        xrootd_cms_server on;
        xrootd_cms_listen_port {CMS_PORT};
        xrootd_access_log {LOG_DIR}/xrootd_access_v4.log;
    }

    server {
        listen [::1]:{MANAGER_V6_PORT} ipv6only=on;
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_manager on;
        xrootd_cms_server on;
        xrootd_cms_listen_port {CMS_PORT};
        xrootd_access_log {LOG_DIR}/xrootd_access_v6.log;
    }
}
```

If a single CMS listener cannot bind both families, split the manager into two
dedicated roles: one IPv4 front door and one IPv6 front door, each with its own
CMS port.

### Dedicated server startup

Extend `tests/manage_test_servers.sh start-all` with these roles:

- `dualstack-v4`
- `dualstack-v6`
- `dualstack-manager`
- `dualstack-ds-v4`
- `dualstack-ds-v6`
- `dualstack-proxy`
- `dualstack-cache`
- `dualstack-tpc-src`
- `dualstack-tpc-dst`

Start data servers after the manager so CMS registration can complete. For
tests that need deterministic redirect order, do not depend on CMS selection
order alone; use a small fixed-port mock redirector or dedicated manager-map
rules that return exactly one target for each test path prefix.

## Test Matrix

### A. Direct IPv4-only transfers

`test_ipv4_literal_upload_download_round_trip`

- Source URL: `root://127.0.0.1:{DUALSTACK_V4_PORT}//ipv4/file.bin`.
- Upload a 4 MiB payload with `xrdcp -f`.
- Download it back with `xrdcp -f`.
- Assert SHA-256 equality.
- Assert access log client IP contains `127.0.0.1`.
- Assert `xrootd_bytes_rx_ipv4_total` and `xrootd_bytes_tx_ipv4_total` for the
  direct server port increased.
- Assert IPv6 byte counters for that port did not increase during this test.

`test_ipv4_only_listener_rejects_ipv6_literal`

- Attempt `xrdfs root://[::1]:{DUALSTACK_V4_PORT}/ ls /`.
- Expect connection failure.
- This proves the test did not accidentally hit a dual-stack wildcard socket.

### B. Direct IPv6-only transfers

`test_ipv6_literal_upload_download_round_trip`

- Source URL: `root://[::1]:{DUALSTACK_V6_PORT}//ipv6/file.bin`.
- Upload a 4 MiB payload with `xrdcp -f`.
- Download it back with `xrdcp -f`.
- Assert SHA-256 equality.
- Assert access log client IP contains `::1` or `[::1]`, depending on nginx
  `addr_text` formatting.
- Assert `xrootd_bytes_rx_ipv6_total` and `xrootd_bytes_tx_ipv6_total` for the
  direct server port increased.
- Assert IPv4 byte counters for that port did not increase during this test.

`test_ipv6_only_listener_rejects_ipv4_literal`

- Attempt `xrdfs root://127.0.0.1:{DUALSTACK_V6_PORT}/ ls /`.
- Expect connection failure.
- This proves the IPv6 listener is not accepting IPv4-mapped connections.

### C. Locate and redirect formatting

`test_locate_self_ipv4_formats_ipv4_hostport`

- Connect to `127.0.0.1:{DUALSTACK_V4_PORT}` with the wire helper.
- Issue `kXR_locate` for a local file.
- Assert locate body contains an IPv4 host and the configured port.
- Assert no brackets are used for IPv4.

`test_locate_self_ipv6_formats_bracketed_ipv6_hostport`

- Connect to `[::1]:{DUALSTACK_V6_PORT}` with the wire helper.
- Issue `kXR_locate` for a local file.
- Assert locate body contains `[::1]:{DUALSTACK_V6_PORT}` or another bracketed
  IPv6 literal.
- Assert the response is not `localhost` and is not an unbracketed IPv6 literal.

`test_redirect_body_preserves_bracketed_ipv6_target`

- Use a fixed mock redirector that returns `kXR_redirect` with host `[::1]` and
  a data-server port.
- Connect through an nginx upstream/manager listener.
- Assert the client-facing redirect body contains bracketed IPv6.

### D. Mixed family selected by first response

These tests prove the family of the data transfer is controlled by the first
response that redirects or locates the client, not by the family of the initial
front-door connection.

`test_ipv6_frontdoor_first_redirects_to_ipv4_data_server`

- Initial client connection: `root://[::1]:{DUALSTACK_MANAGER_V6_PORT}/`.
- First response: `kXR_redirect` to `127.0.0.1:{DUALSTACK_DS_V4_PORT}`.
- Data file exists only on the IPv4 data server.
- Run `xrdcp -f` through the IPv6 manager URL.
- Assert download succeeds and SHA-256 matches the IPv4 data-server file.
- Assert manager IPv6 access log saw the initial request.
- Assert IPv4 data-server access log saw `OPEN` and `READ`.
- Assert IPv6 data-server access log did not see that path.
- Assert IPv6 manager byte counters and IPv4 data-server byte counters both
  increased.

`test_ipv4_frontdoor_first_redirects_to_ipv6_data_server`

- Initial client connection: `root://127.0.0.1:{DUALSTACK_MANAGER_V4_PORT}/`.
- First response: `kXR_redirect` to `[::1]:{DUALSTACK_DS_V6_PORT}`.
- Data file exists only on the IPv6 data server.
- Run `xrdcp -f` through the IPv4 manager URL.
- Assert download succeeds and SHA-256 matches the IPv6 data-server file.
- Assert manager IPv4 access log saw the initial request.
- Assert IPv6 data-server access log saw `OPEN` and `READ`.
- Assert IPv4 data-server access log did not see that path.
- Assert IPv4 manager byte counters and IPv6 data-server byte counters both
  increased.

`test_first_redirect_order_selects_first_family`

- Use a mock redirector or deterministic manager rule that can return one of
  two redirects for two different path prefixes:
  - `/first-v4/...` returns IPv4 first.
  - `/first-v6/...` returns IPv6 first.
- Run one transfer for each prefix through the same front-door listener.
- Assert `/first-v4/...` is served by the IPv4 data server.
- Assert `/first-v6/...` is served by the IPv6 data server.
- Assert the non-selected data server did not open the file.

`test_wait_then_redirect_uses_redirect_family`

- First response is `kXR_wait` or `kXR_waitresp`.
- Final redirect response points to `[::1]:{DUALSTACK_DS_V6_PORT}`.
- Run `xrdcp`.
- Assert transfer completes through IPv6 data server.
- Repeat with final redirect to `127.0.0.1:{DUALSTACK_DS_V4_PORT}`.

### E. Secondary connections and bind

`test_xrdcp_streams_bind_follows_ipv4_redirect_family`

- Use `xrdcp --streams 4` through a front door that redirects first to the IPv4
  data server.
- Assert the IPv4 data-server access log contains `BIND` entries.
- Assert those entries use an IPv4 client address.
- Assert the IPv6 data server saw no `BIND` for the path.

`test_xrdcp_streams_bind_follows_ipv6_redirect_family`

- Same as above, but first redirect points to `[::1]:{DUALSTACK_DS_V6_PORT}`.
- Assert `BIND` entries appear on the IPv6 data server with an IPv6 client
  address.

### F. Module-owned outbound connection paths

These tests cover code paths where nginx-xrootd initiates outbound stream
connections and therefore must be dual-stack safe.

`test_upstream_redirector_ipv6_backend_transfer`

- Configure `xrootd_upstream [::1]:{BACKEND_PORT};`.
- Backend returns a redirect to the IPv6 data server.
- Request a path missing locally.
- Assert `xrdcp` succeeds and backend accepted an IPv6 connection from nginx.

`test_proxy_mode_ipv6_upstream_transfer`

- Configure proxy mode with `xrootd_proxy_upstream [::1]:{DUALSTACK_DS_V6_PORT};`.
- Upload and download through `root://127.0.0.1:{DUALSTACK_PROXY_PORT}/`.
- Assert upstream data server logs IPv6 connections from nginx.
- Assert bytes match.

`test_cache_origin_ipv6_transfer`

- Configure cache origin as `root://[::1]:{DUALSTACK_DS_V6_PORT}`.
- Fetch a file through the cache listener.
- Assert first read populates cache from IPv6 origin.
- Assert second read is served from cache.
- Assert origin logs exactly one read for the path.

`test_native_tpc_ipv6_source_to_ipv4_destination`

- Source URL uses `[::1]:{DUALSTACK_TPC_SRC_PORT}`.
- Destination URL uses `127.0.0.1:{DUALSTACK_TPC_DST_PORT}`.
- Run native root TPC with `xrdcp --tpc only`.
- Assert destination file hash matches source.
- Assert source saw IPv6 traffic and destination saw IPv4 traffic.

`test_native_tpc_ipv4_source_to_ipv6_destination`

- Reverse the previous test.
- Assert source saw IPv4 traffic and destination saw IPv6 traffic.

### G. Security-negative checks

`test_unbracketed_ipv6_redirect_is_rejected_or_never_emitted`

- If a mock upstream sends `::1:11235` without brackets, nginx should either
  reject it when parsing or pass it through only in a test marked as expected
  client failure.
- The primary invariant is that nginx-generated redirects and locates never
  emit unbracketed IPv6 literals.

`test_ipv6_private_and_loopback_ssrf_policy`

- Reuse the TPC SSRF policy fixtures with URLs containing:
  - `root://[::1]:...`
  - `root://[fe80::1]:...`
  - `root://[fc00::1]:...`
  - `root://[::ffff:127.0.0.1]:...`
- Assert default policy denies loopback, link-local, ULA, and IPv4-mapped
  loopback unless the dedicated allow-local policy is enabled.

`test_authdb_ipv6_cidr_host_rules`

- Configure one dedicated listener with authdb host rules for `::1/128`.
- Assert `[::1]` transfer is allowed.
- Assert `127.0.0.1` transfer is denied.

## Pass/Fail Signals

Every transfer test should assert at least three independent signals:

- Client success: `xrdcp` return code is zero and SHA-256 matches.
- Routing proof: the expected dedicated server access log contains `OPEN`,
  `READ`, `WRITE`, or `BIND` for the test path.
- Family proof: per-port IPv4 or IPv6 byte counters increased only for the
  expected family, or a mock server recorded the accepted socket family.

For mixed tests, also assert the negative routing signal:

- The non-selected data server did not log the test path.

## Implementation Order

1. Add IPv6 loopback probe and helpers in `tests/test_dual_stack_transfers.py`.
2. Add direct IPv4 and IPv6 dedicated listeners.
3. Implement direct upload/download tests and metrics assertions.
4. Add wire-level locate tests for IPv4 and IPv6 formatting.
5. Add deterministic first-response redirect fixtures.
6. Add mixed IPv4-to-IPv6 and IPv6-to-IPv4 transfer tests.
7. Add `--streams` secondary bind coverage.
8. Add proxy, cache-origin, and native TPC outbound-family tests.
9. Add SSRF and authdb security-negative coverage.

## Likely Code Fixes Exposed By This Plan

The tests are expected to expose the gaps already documented in
`docs/09-developer-guide/ipv6-dual-stack.md`:

- `src/net/upstream/start.c` must use `getaddrinfo(AF_UNSPEC)` rather than
  `AF_INET`, `inet_addr()`, and `gethostbyname()`.
- `src/net/proxy/connect.c` must use `getaddrinfo(AF_UNSPEC)` and iterate returned
  addresses.
- `src/net/proxy/directives.c` must parse bracketed IPv6 upstream addresses.
- `src/read/locate.c` must format IPv6 locate entries as bracketed literals and
  must not fall back to `localhost`.
- Any local-port extraction from `c->local_sockaddr` must branch on
  `AF_INET` vs `AF_INET6`.

## Commands

Targeted direct and mixed transfer suite:

```bash
PYTHONPATH=tests pytest tests/test_dual_stack_transfers.py -v
```

Run only direct listeners:

```bash
PYTHONPATH=tests pytest tests/test_dual_stack_transfers.py -k "direct or locate" -v
```

Run only mixed first-response behavior:

```bash
PYTHONPATH=tests pytest tests/test_dual_stack_transfers.py -k "first_redirect or wait_then_redirect or streams_bind" -v
```

Full regression after module-owned outbound fixes:

```bash
PYTHONPATH=tests pytest tests/test_dual_stack_transfers.py tests/test_tpc_ssrf_policy.py tests/test_proxy_mode.py tests/test_root_tpc.py -v
```

## Acceptance Criteria

- IPv4-only direct transfers pass and IPv6 attempts to the IPv4-only listener
  fail.
- IPv6-only direct transfers pass and IPv4 attempts to the IPv6-only listener
  fail.
- `kXR_locate` and `kXR_redirect` responses use bracketed IPv6 literals.
- Mixed IPv4 front-door to IPv6 data-server transfers pass.
- Mixed IPv6 front-door to IPv4 data-server transfers pass.
- When the first response chooses IPv4, only the IPv4 data server handles the
  data path.
- When the first response chooses IPv6, only the IPv6 data server handles the
  data path.
- Secondary `kXR_bind` connections follow the selected data-server family.
- Proxy mode, cache origin fetches, and native TPC complete over IPv6 where the
  configured target is IPv6.
- Security-negative tests reject unsafe IPv6 and IPv4-mapped IPv6 addresses.
