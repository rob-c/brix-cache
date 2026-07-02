# Dual-Stack IPv4+IPv6 Support

## Scope and motivation

What dual-stack IPv4+IPv6 testing requires, where the code currently fails, and where the protocol specs, RFCs, and reference XRootD implementation are ambiguous.

**Goal**: Produce a test plan that covers every code path that creates, binds, connects,
or formats IP addresses — plus the protocol semantics of how IPv6 addresses are conveyed
in XRootD wire responses.

**Why now**: HEP federations are gradually deploying IPv6. Clients on IPv6-only networks
cannot reach servers that only listen on IPv4 or return IPv4-only redirect addresses.
The reference `xrootd` daemon has supported dual-stack for years; nginx-xrootd has
partial but inconsistent support.

---

## 2. Architecture: Where IP Addresses Flow

Understanding dual-stack support requires tracing IP addresses through three layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Listen / Accept (nginx core)                          │
│  "listen port;" → kernel socket → c->local_sockaddr             │
│  Dual-stack: nginx handles this via kernel IPV6_V6ONLY policy   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Outbound Connect (module code)                        │
│  upstream/proxy/cache/tpc → socket() + connect()                │
│  Uses: AF_INET+inet_addr+gethostbyname (broken) or              │
│        AF_UNSPEC+getaddrinfo (correct)                          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Response Formatting (module code)                     │
│  kXR_locate, kXR_redirect, stats XML → host:port string         │
│  Uses: inet_ntoa (broken, race), inet_ntop (correct),           │
│        ngx_sock_ntop (correct), getnameinfo (correct)           │
└─────────────────────────────────────────────────────────────────┘
```

**Key insight**: The codebase has three distinct patterns for address handling:

| Pattern | Function | Dual-stack? | Where used |
|---------|----------|-------------|------------|
| **Broken** | Unconditional `(struct sockaddr_in*)` cast | No | `cache/thread.c`, `cache/evict.c` |
| **Broken** | `ngx_strlchr(..., ':')` for port parsing | No | `proxy/directives.c` |
| **Broken** | `inet_ntoa()` in multi-threaded context | Race | `read/locate.c` |
| **Correct** | `getaddrinfo(AF_UNSPEC)` + addrinfo iteration | Yes | `tpc/connect.c`, `cache/origin_connection.c`, `upstream/start.c`, `proxy/connect_upstream.c` |
| **Correct** | `ngx_sock_ntop()` | Yes | `cache/thread.c` (addr only), `cms/server_handler.c` |
| **Correct** | `getnameinfo()` | Yes | `tpc/launch.c` |
| **Correct** | `ngx_parse_url()` | Yes | `cms/config.c` |
| **Correct** | Bracket-aware `[addr]:port` parsing | Yes | `upstream/directives.c`, `config/manager_map.c`, `cache/directives.c` |

---

## 3. Current State — Full Audit by Source File

### 3.1 Dual-stack ready — correct patterns

| File | What it does | Why it's OK |
|------|-------------|-------------|
| `src/tpc/connect.c` | TPC outbound TCP connect | `getaddrinfo(AF_UNSPEC)`, iterates all addrinfo entries, IPv6 SSRF checks in `tpc_addr_is_prohibited()` |
| `src/fs/cache/origin_connection.c` | Cache-fill origin connect | `getaddrinfo(AF_UNSPEC)`, iterates all addrinfo entries |
| `src/net/cms/config.c` | CMS manager address parsing | Uses `ngx_parse_url()` which handles IPv6 literals via nginx's internal resolver |
| `src/net/upstream/directives.c` | `xrootd_upstream host:port` parsing | Lines 24–54: checks for `[` prefix, extracts IPv6 address between brackets |
| `src/core/config/manager_map.c` | `xrootd_manager_map prefix host:port` parsing | Lines 49–77: same bracket-aware IPv6 parsing |
| `src/fs/cache/directives.c` | `xrootd_cache_origin host:port` parsing | Lines 62–90: same bracket-aware IPv6 parsing, handles `root://` and `roots://` prefixes |
| `src/connection/handler.c` (lines 93–106) | Port extraction from `c->local_sockaddr` | Lines 93–106: checks `sa_family` and casts to correct type for `AF_INET` and `AF_INET6` |
| `src/tpc/launch.c` (lines 82–86) | Client address for TPC logging | `getnameinfo()` with `NI_NAMEREQD` — dual-stack safe |
| `src/observability/accesslog/access_log.c` | Access log client IP | Uses `c->addr_text` — nginx's pre-formatted address string which includes brackets for IPv6 |
| `src/net/cms/server_handler.c` (line 23) | Server address logging | `ngx_sock_ntop()` — nginx's dual-stack address formatter |

### 3.2 Outbound connects — **[RESOLVED]** (formerly P0: IPv4-only)

These were the most impactful gaps because they blocked manager-mode redirects and
transparent proxying on IPv6 networks entirely. Both call sites have since been
converted to dual-stack and are documented below for historical reference.

#### `src/net/upstream/start.c` — **[RESOLVED]**

This previously hardcoded `AF_INET` + `inet_addr()` + `gethostbyname()`. The current
code is dual-stack: the fast path (pre-resolved config address) uses
`conf->upstream_addr->sockaddr` and creates the socket with that address's
`sa_family`, and the fallback path resolves per-request with
`getaddrinfo(AF_UNSPEC)` and iterates all returned addrinfo entries. The chosen
address is stored in a `struct sockaddr_storage`, so IPv6 backends connect
correctly.

**Status**: Outbound IPv6 connect from the upstream redirector
(`kXR_locate` miss → redirect to `xrootd_upstream`) and manager-mode redirects
to IPv6 backends are supported.

#### `src/net/proxy/connect_upstream.c` — **[RESOLVED]**

The proxy connect path was previously `src/net/proxy/connect.c` with the identical
IPv4-only anti-pattern. It is now `src/net/proxy/connect_upstream.c`, which resolves
via `getaddrinfo(AF_UNSPEC)`, iterates addrinfo entries, and stores the endpoint
in a `struct sockaddr_storage`.

**Status**: Transparent proxy mode (`xrootd_proxy on`) connects to IPv6 upstream
XRootD daemons.

### 3.3 P1 failures — IPv4-only address formatting in responses

#### `src/read/locate.c` (lines 114–123)

```c
if (c->local_sockaddr != NULL
    && c->local_sockaddr->sa_family == AF_INET)
{
    sin = (struct sockaddr_in *) c->local_sockaddr;
    port = ntohs(sin->sin_port);
    snprintf(addr_buf, sizeof(addr_buf), "%s:%d",
             inet_ntoa(sin->sin_addr), (int) port);
} else {
    snprintf(addr_buf, sizeof(addr_buf), "localhost");
}
```

**Problems**:
1. IPv6 branch falls through to `"localhost"` — not a valid XRootD server address
2. `inet_ntoa()` returns a pointer to static internal storage — data race in nginx's
   multi-threaded worker model (multiple connections could corrupt the buffer)
3. IPv6 addresses in XRootD responses MUST be bracketed (`[addr]:port`) per RFC 3986

**Impact**: IPv6 clients receive `Srlocalhost` or `Swlocalhost` from `kXR_locate`,
which the XRootD client cannot parse or connect to.

#### `src/query/metadata.c` (lines 83–89)

```c
if (port == 0) {
    struct sockaddr_in *sin = (struct sockaddr_in *) c->local_sockaddr;
    if (sin && c->local_sockaddr->sa_family == AF_INET) {
        port = (int) ntohs(sin->sin_port);
    }
}
```

**Problem**: Port is only extracted from `AF_INET`. For IPv6 listeners, the port
field in the XML stats response is `0`.

**Impact**: `kXR_query` stats response shows port 0 for IPv6 listeners.

#### `src/fs/cache/thread.c` (lines 125–126)

```c
self_port = ntohs(
    ((struct sockaddr_in *) c->local_sockaddr)->sin_port);
```

**Problem**: Unconditional cast to `sockaddr_in*` for port extraction. The preceding
`ngx_sock_ntop()` call (line 122) is dual-stack safe, but the port extraction is not.

**Impact**: Cache registration in manager mode reports wrong port for IPv6 listeners.

#### `src/fs/cache/evict.c` (lines 406–407)

Identical bug to `cache/thread.c`:

```c
self_port = ntohs(
    ((struct sockaddr_in *) t->c->local_sockaddr)->sin_port);
```

**Impact**: Cache unregistration in manager mode reports wrong port for IPv6 listeners.

### 3.4 P1 failures — Configuration parsing

#### `src/net/proxy/directives.c` (lines 23–24)

```c
colon = ngx_strlchr(value[1].data,
                    value[1].data + value[1].len, ':');
```

**Problem**: `ngx_strlchr()` finds the *last* colon in the string. For an IPv6 address
like `[2001:db8::1]:1094`, this finds the colon inside the brackets (the second one
in `db8::1`), not the port separator after `]`. The resulting host string would be
garbled and the port extraction would fail.

**Impact**: `xrootd_proxy_upstream [::1]:1094;` config directive fails to parse.

**Note**: This is inconsistent with `upstream/directives.c`, `config/manager_map.c`,
and `cache/directives.c` which all correctly handle bracketed IPv6.

### 3.5 SSRF guard — already dual-stack (model for others)

`src/tpc/connect.c::tpc_addr_is_prohibited()` (lines 29–126) is the reference
implementation for dual-stack address classification:

- **IPv4**: checks 127/8, 169.254/16, 10/8, 172.16/12, 192.168/16
- **IPv6**: checks `::1`, `fe80::/10`, `fc00::/7` (ULA)
- **v4-mapped**: `::ffff:x.x.x.x` is classified using IPv4 rules (line 111–118)

This should be the template for any other code that classifies addresses.

### 3.6 What's OK — layers that don't need changes

| Layer | Why it's OK |
|-------|-------------|
| **WebDAV** (`src/protocols/webdav/`) | No direct socket code. Uses nginx's HTTP request machinery. TCP listening/connecting is handled by nginx core. TPC URLs come from HTTP headers (`Source:`, `Destination:`) and are passed verbatim to curl, which understands bracketed IPv6. |
| **S3** (`src/protocols/s3/`) | No direct socket code. Same as WebDAV — uses nginx HTTP layer. |
| **Metrics** (`src/observability/metrics/`) | No IP address handling. Uses shared atomic counters with fixed labels. |
| **Response module** (`src/response/`) | `xrootd_send_redirect()` takes a `host` string and `port` number. The host string is embedded verbatim into the wire response. IPv6 formatting responsibility is on the *callers* (see §3.3). |
| **CMS protocol** | The CMS heartbeat sends `listen_port` but not hostname; the CMS manager provides the hostname in `kYR_select` redirects. The CMS subsystem doesn't format IPv6 addresses itself — it delegates to the CMS manager. This is a protocol-level dependency. |

---

## 4. Standards and Protocol Ambiguities

### 4.1 XRootD `kXR_locate` response format for IPv6

The `kXR_locate` opcode returns a response body like `Sr192.168.1.1:1094` or
`Sw[2001:db8::1]:1094`. The question is: **does the XRootD wire protocol specification
require or allow bracketed IPv6 addresses in the locate response?**

| Source | Position |
|--------|----------|
| **RFC 3986 §3.2.2** | URIs containing IPv6 literals MUST use brackets: `http://[2001:db8::1]:8080/path` |
| **RFC 5533 §3** | DNS resolution for application protocols recommends that servers return addresses in a format clients can parse unambiguously |
| **Reference XRootD** | Returns bracketed IPv6 addresses in `kXR_locate` responses |
| **XRootD wire spec** | Does not explicitly mandate bracket notation — the response is an opaque string |
| **Python XRootD client** | Parses bracketed IPv6 in redirect/locate responses |
| **C++ XRootD client** | Parses bracketed IPv6 in redirect/locate responses |

**Conclusion**: While the wire protocol doesn't explicitly mandate brackets, the
reference implementation and all known clients expect them. Returning unbracketed
IPv6 (or `"localhost"`) will cause client parsing failures.

### 4.2 `kXR_redirect` response format

Redirect responses (`xrootd_send_redirect()`) accept a `host` string and `port`
number. The host string is embedded verbatim into the wire response. This means:

- Config-time IPv6 literals (`[::1]:1094`) will be returned as-is (correct).
- The caller must ensure the host string is bracketed for IPv6.
- Manager-mode redirects get the host from the CMS registry, which gets it from the
  CMS manager — a chain of trust that depends on each link formatting correctly.

**Ambiguity**: The manager registry (`src/net/manager/registry.c`) stores host strings
as opaque text from heartbeats. The CMS login heartbeat (line 132–134 of `send.c`)
sends empty host/port trailer fields, meaning the CMS manager infers the server's
address from the TCP connection. This is correct for the CMS→manager path, but
the manager→redirect path depends on the CMS manager formatting IPv6 correctly.

### 4.3 nginx `listen` directive and `IPV6_V6ONLY`

The behavior of bare `listen port;` (no address specified) in the `stream {}` block
depends on the OS kernel:

| OS / Kernel | Default `IPV6_V6ONLY` | Behavior |
|-------------|----------------------|----------|
| Linux ≥ 4.10 | `0` (dual-stack) | Listens on both `0.0.0.0` and `[::]`, IPv4 connections arrive as v4-mapped IPv6 (`::ffff:x.x.x.x`) |
| Linux < 4.10 | Varies | May listen on `0.0.0.0` only, or dual-stack with unpredictable behavior |
| macOS | `0` (dual-stack) | Dual-stack by default |
| Windows | `0` (dual-stack) | Dual-stack by default |
| FreeBSD | `1` (IPv6-only) | `listen port;` binds IPv6 only; need separate `listen 0.0.0.0:port;` for IPv4 |

**Test implication**: Tests that rely on bare `listen port;` may behave differently
across platforms. For deterministic testing, explicitly specify `listen [::]:port;`
(dual-stack on Linux) or `listen 0.0.0.0:port;` (IPv4 only).

### 4.4 `gethostbyname()` deprecation

`gethostbyname()` (formerly used in `upstream/start.c` and `proxy/connect.c`, both
now converted to `getaddrinfo()` — see §3.2) is officially deprecated per
RFC 2553 §3.1:

> The `gethostbyname()` interface is superseded by `getaddrinfo()`. Applications
> should use `getaddrinfo()` for both forward and reverse name translations.

`gethostbyname()` has additional problems:
- Returns only IPv4 addresses
- Not thread-safe (uses static internal storage for `hostent`)
- No error code — sets `h_errno` which is per-thread but easy to miss
- No timeout control

### 4.5 `inet_ntoa()` thread safety

`src/read/locate.c` uses `inet_ntoa()` which returns a pointer to static internal
storage shared across all threads. In nginx's multi-threaded worker model:

```
Thread A: inet_ntoa(192.168.1.1) → returns pointer to "192.168.1.1"
Thread B: inet_ntoa(10.0.0.1)   → returns SAME pointer, now contains "10.0.0.1"
Thread A: uses the buffer → gets "10.0.0.1" (corrupted)
```

The correct replacement is `inet_ntop()` with a caller-allocated buffer. The buffer
is already allocated in `locate.c` as `addr_buf[INET6_ADDRSTRLEN + 8]` — it just
doesn't use `inet_ntop()`.

### 4.6 XRootD client behavior with IPv6

| Client | IPv6 support | Notes |
|--------|-------------|-------|
| `xrdcp` (C++) | Full | Handles bracketed IPv6 in URLs and redirects |
| `xrdfs` (C++) | Full | Same as xrdcp |
| Python `XRootD` | Full | Handles bracketed IPv6, uses `getaddrinfo` |
| `xrootd` daemon (reference) | Full | Dual-stack since v4.8+, `IPV6_V6ONLY` configurable |

---

## 5. Test Plan

### 5.1 Unit-level tests (per-module)

#### 5.1.1 Upstream redirector (`src/net/upstream/start.c`)

| Test | Description | Expected |
|------|-------------|----------|
| `test_upstream_ipv4_dns` | Upstream host resolves to A record | Connects via IPv4 |
| `test_upstream_ipv6_dns` | Upstream host resolves to AAAA record | Connects via IPv6 |
| `test_upstream_dual_dns` | Upstream host resolves to both A and AAAA | Tries both, uses first successful |
| `test_upstream_ipv4_literal` | `xrootd_upstream 192.168.1.1:1094;` | Connects to IPv4 literal |
| `test_upstream_ipv6_literal` | `xrootd_upstream [::1]:1094;` | Connects to IPv6 literal |
| `test_upstream_no_ipv6_backend` | IPv6-only backend unreachable | Returns meaningful error, not crash |

#### 5.1.2 Proxy mode (`src/net/proxy/connect_upstream.c`)

| Test | Description | Expected |
|------|-------------|----------|
| `test_proxy_ipv4_upstream` | `xrootd_proxy_upstream 192.168.1.1:1094;` | Bootstrap succeeds |
| `test_proxy_ipv6_upstream` | `xrootd_proxy_upstream [::1]:1094;` | Bootstrap succeeds |
| `test_proxy_ipv6_config_parse` | `xrootd_proxy_upstream [2001:db8::1]:1094;` | Config parses correctly (currently fails) |
| `test_proxy_dual_upstream` | Upstream resolves to both A and AAAA | Tries both address families |

#### 5.1.3 kXR_locate response (`src/read/locate.c`)

| Test | Description | Expected |
|------|-------------|----------|
| `test_locate_ipv4_response` | IPv4 client (`127.0.0.1`) | Response: `S[rw]127.0.0.1:<port>` |
| `test_locate_ipv6_response` | IPv6 client (`::1`) | Response: `S[rw][::1]:<port>` (not `"localhost"`) |
| `test_locate_dual_stack` | Server on dual-stack, both client types | Both get correct address family |
| `test_locate_inet_ntoa_safety` | Many concurrent IPv6 connections | No buffer corruption in logs |
| `test_locate_v4mapped_client` | IPv4-mapped IPv6 client (`::ffff:x.x.x.x`) | Returns IPv4 address, not "localhost" |

#### 5.1.4 Query stats (`src/query/metadata.c`)

| Test | Description | Expected |
|------|-------------|----------|
| `test_stats_ipv4_port` | IPv4 listener | XML `<port>` contains correct port |
| `test_stats_ipv6_port` | IPv6 listener | XML `<port>` contains correct port (not 0) |

#### 5.1.5 Cache registration (`src/fs/cache/thread.c`, `src/fs/cache/evict.c`)

| Test | Description | Expected |
|------|-------------|----------|
| `test_cache_register_ipv4` | Cache fill on IPv4 listener | Registry entry has correct port |
| `test_cache_register_ipv6` | Cache fill on IPv6 listener | Registry entry has correct port (not garbage from wrong cast) |
| `test_cache_unregister_ipv6` | Cache eviction on IPv6 listener | Unregister uses correct port |

### 5.2 Integration tests (end-to-end)

#### 5.2.1 IPv6 loopback path

| Test | Description |
|------|-------------|
| `test_xrootd_ipv6_anon` | Anonymous `root://[::1]:<port>` — open/read/close |
| `test_xrootd_ipv6_gsi` | GSI-authenticated `roots://[::1]:<port>` — TLS from byte 0 |
| `test_xrootd_ipv6_token` | Token-authenticated `root://[::1]:<port>` |
| `test_xrootd_ipv6_write` | Write operations over IPv6 (pgwrite, sync, truncate) |
| `test_xrootd_ipv6_dirlist` | Directory listing over IPv6 |
| `test_xrootd_ipv6_query` | Query ops (checksum, space, config) over IPv6 |
| `test_webdav_ipv6` | `davs://[::1]:<port>` — GET/PUT/DELETE/MKCOL/PROPFIND |
| `test_s3_ipv6` | `http://[::1]:<port>` — GET/PUT/ListObjectsV2 |

#### 5.2.2 Manager mode with IPv6 backends

| Test | Description |
|------|-------------|
| `test_manager_redirect_ipv6` | Static `xrootd_manager_map` points to `[::1]:<port>` — verify redirect contains brackets |
| `test_manager_locate_ipv6` | `kXR_locate` on IPv6 client returns bracketed IPv6 address |
| `test_manager_upstream_ipv6` | Dynamic upstream redirector connects to IPv6 backend |
| `test_manager_cache_register_ipv6` | Cache registration on IPv6 listener reports correct port to manager |
| `test_manager_cms_locate_ipv6` | CMS-sourced locate redirect contains valid IPv6 address |

#### 5.2.3 TPC with IPv6

| Test | Description |
|------|-------------|
| `test_tpc_pull_ipv6_source` | TPC pull from IPv6 source server |
| `test_tpc_push_ipv6_dest` | TPC push to IPv6 destination |
| `test_tpc_ipv6_ssrf_blocked` | IPv6 loopback/ULA addresses rejected by SSRF guard |
| `test_tpc_ipv6_v4mapped` | v4-mapped IPv6 address classified as IPv4 by SSRF guard |
| `test_tpc_ipv6_logging` | TPC launch uses `getnameinfo()` correctly for IPv6 client addresses |

#### 5.2.4 Cache origin with IPv6

| Test | Description |
|------|-------------|
| `test_cache_origin_ipv6` | Cache fill from IPv6 origin — verify data integrity |
| `test_cache_origin_ipv6_tls` | TLS cache fill from IPv6 origin |
| `test_cache_origin_ipv6_config` | `xrootd_cache_origin [::1]:1094;` — config parses correctly |

#### 5.2.5 WebDAV HTTP-TPC with IPv6

| Test | Description |
|------|-------------|
| `test_webdav_tpc_pull_ipv6` | COPY pull from `https://[::1]:<port>/` source |
| `test_webdav_tpc_push_ipv6` | COPY push to `https://[::1]:<port>/` destination |

### 5.3 Configuration-level tests

| Test | Description |
|------|-------------|
| `test_listen_ipv4_only` | `listen 127.0.0.1:port;` — only IPv4 connections accepted |
| `test_listen_ipv6_only` | `listen [::]:port;` — only IPv6 connections accepted |
| `test_listen_unspecified_linux` | `listen port;` on Linux ≥ 4.10 — dual-stack behavior verified |
| `test_listen_unspecified_freebsd` | `listen port;` on FreeBSD — verify IPv4-only (need explicit `0.0.0.0`) |
| `test_upstream_directive_ipv6` | `xrootd_upstream [::1]:1094;` — parses correctly |
| `test_manager_map_directive_ipv6` | `xrootd_manager_map /prefix [::1]:1094;` — parses correctly |
| `test_cache_origin_directive_ipv6` | `xrootd_cache_origin [::1]:1094;` — parses correctly |
| `test_cache_origin_directive_ipv6_tls` | `xrootd_cache_origin roots://[::1]:1094;` — enables TLS + parses IPv6 |
| `test_proxy_upstream_directive_ipv6` | `xrootd_proxy_upstream [::1]:1094;` — parses correctly (currently fails) |
| `test_cms_manager_ipv6` | `xrootd_cms_manager [::1]:port;` — CMS heartbeat connects |

### 5.4 Negative tests

| Test | Description |
|------|-------------|
| `test_locate_ipv6_no_brackets` | Verify locate response does NOT return unbracketed IPv6 like `::1:1094` |
| `test_locate_ipv6_not_localhost` | Verify locate response does NOT return `"localhost"` for IPv6 |
| `test_redirect_ipv6_no_brackets` | Verify redirect does NOT return unbracketed IPv6 |
| `test_upstream_ipv6_connect_timeout` | IPv6-only backend unreachable — verify timeout is reasonable, not hang |
| `test_proxy_ipv6_connect_timeout` | Proxy to IPv6-only backend — verify error path, not crash |
| `test_stats_ipv6_zero_port` | Verify stats port is never zero for IPv6 listener |
| `test_inet_ntoa_race` | Stress test with many concurrent IPv6 connections — no log corruption |
| `test_proxy_config_invalid_ipv6` | `xrootd_proxy_upstream [::1];` (no port) — should fail config validation |
| `test_proxy_config_malformed_ipv6` | `xrootd_proxy_upstream [::1:1094;` (missing `]`) — should fail config validation |

### 5.5 Cross-backend conformance

| Test | Description |
|------|-------------|
| `test_locate_ipv6_conformance` | Compare `kXR_locate` response between nginx-xrootd and reference xrootd on IPv6 |
| `test_stats_ipv6_conformance` | Compare XML stats format on IPv6 listener |
| `test_xrdcp_ipv6` | `xrdcp` transfers over IPv6 — compare data integrity with reference xrootd |
| `test_xrdcp_ipv6_redirect` | xrdcp follows IPv6 redirect — compare with reference xrootd behavior |
| `test_python_client_ipv6` | Python XRootD client over IPv6 — compare with reference xrootd |

### 5.6 Platform-specific tests

| Test | Description |
|------|-------------|
| `test_dual_stack_kernel_support` | Verify host kernel supports `IPV6_V6ONLY` |
| `test_v4mapped_ipv6_socket` | IPv4 connection on dual-stack socket arrives as `::ffff:x.x.x.x` |
| `test_freebsd_listen_behavior` | On FreeBSD, verify `listen port;` is IPv6-only |

---

## 6. Infrastructure Required for Testing

### 6.1 Host requirements

1. **IPv6 loopback**: `::1` must be available.
   ```bash
   ip -6 addr show lo | grep -q 'inet6 ::1'
   # or: ifconfig lo | grep -i inet6
   ```

2. **Dual-stack kernel**: Linux ≥ 4.10 recommended for predictable `IPV6_V6ONLY=0`
   default. Older kernels may not dual-stack bare `listen port;`.

3. **Test IPv6 addresses**: For non-loopback tests, use:
   - Documentation range: `2001:db8::/32` (never routes externally)
   - ULA: `fd00::/8` (locally unique, never routes)
   - Link-local: `fe80::/10` (only valid on local interface, needs scope ID)

### 6.2 Test harness modifications

#### 6.2.1 IPv6 test fixtures in `conftest.py`

```python
@pytest.fixture(scope="session")
def test_env_ipv6():
    """Test environment configured for IPv6 loopback connections."""
    ports = { ... same as test_env ... }
    return {
        **ports,
        "anon_url": f"root://[::1]:{ports['anon_port']}",
        "gsi_url": f"roots://[::1]:{ports['gsi_tls_port']}",
        "token_url": f"root://[::1]:{ports['token_port']}",
        "webdav_url": f"https://[::1]:{ports['webdav_port']}",
        "http_webdav_url": f"http://[::1]:{ports['http_webdav_port']}",
        "s3_url": f"http://[::1]:{ports['s3_port']}",
        "metrics_url": f"http://[::1]:{ports['metrics_port']}/metrics",
    }
```

#### 6.2.2 IPv6 config templates

Add `tests/configs/nginx_shared_ipv6.conf` with:

```nginx
stream {
    server {
        listen [::]:{ANON_PORT};      # dual-stack on Linux
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
    }
    server {
        listen [::]:{GSI_PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth gsi;
        # ... certs ...
    }
    # ... other servers ...
}

http {
    server {
        listen [::]:{WEBDAV_PORT} ssl;
        # ...
    }
    # ...
}
```

#### 6.2.3 Environment variable support

```bash
# Override test addresses for IPv6 testing
TEST_NGINX_IPV6_URL=root://[::1]:11094 pytest tests/test_file_api.py -v

# Skip IPv6 tests when ::1 unavailable
TEST_SKIP_IPV6=1 pytest tests/ -v
```

#### 6.2.4 Conditional test skipping

```python
import socket

def skip_if_no_ipv6():
    """Skip test if IPv6 loopback is unavailable."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(("::1", 0))
        sock.close()
    except OSError:
        pytest.skip("IPv6 loopback not available")
```

### 6.3 Reference xrootd IPv6 testing

Start reference xrootd with IPv6-binding configuration:

```
xrd.port 11098
xrd.network nodnr
# xrootd listens on all interfaces by default; verify:
# ss -tlnp6 | grep 11098
```

Cross-compatibility tests should run against both IPv4 and IPv6 reference instances.

---

## 7. Implementation Fixes Required Before Testing

### 7.1 P0 — Fix outbound IPv4-only connect code — **[IMPLEMENTED]**

**Files**: `src/net/upstream/start.c`, `src/net/proxy/connect_upstream.c`

The `AF_INET` + `inet_addr()` + `gethostbyname()` pattern has been replaced with
`getaddrinfo(AF_UNSPEC)` + addrinfo iteration in both call sites. The fast path in
`upstream/start.c` uses the pre-resolved config sockaddr (creating the socket with
its `sa_family`); the fallback path and `proxy/connect_upstream.c` resolve
per-request with `getaddrinfo(AF_UNSPEC)`, iterate all returned entries, and store
the chosen endpoint in a `struct sockaddr_storage`.

**Reference implementations in this codebase**:
- `src/net/upstream/start.c` — upstream redirector connect (dual-stack)
- `src/net/proxy/connect_upstream.c` — proxy upstream connect (dual-stack)
- `src/tpc/connect.c` — TPC connect
- `src/fs/cache/origin_connection.c` — cache origin connect

### 7.2 P1 — Fix kXR_locate IPv6 response

**File**: `src/read/locate.c` (lines 114–123)

```c
if (c->local_sockaddr != NULL) {
    if (c->local_sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->local_sockaddr;
        port = ntohs(sin->sin_port);
        inet_ntop(AF_INET, &sin->sin_addr, addr_buf, sizeof(addr_buf));
        snprintf(loc_buf, sizeof(loc_buf), "S%c%s:%d", access_char, addr_buf, port);
    } else if (c->local_sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
        port = ntohs(sin6->sin6_port);
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, sizeof(addr_buf));
        snprintf(loc_buf, sizeof(loc_buf), "S%c[%s]:%d", access_char, addr_buf, port);
    } else {
        snprintf(loc_buf, sizeof(loc_buf), "S%clocalhost", access_char);
    }
} else {
    snprintf(loc_buf, sizeof(loc_buf), "S%clocalhost", access_char);
}
```

Key differences from current code:
- IPv6 branch uses `inet_ntop()` instead of falling through to `"localhost"`
- IPv6 address is **bracketed** (`[%s]:%d`) per RFC 3986 convention
- `inet_ntop()` replaces `inet_ntoa()` — thread-safe, uses caller buffer

### 7.3 P1 — Fix proxy_upstream IPv6 config parsing

**File**: `src/net/proxy/directives.c`

Replace the `ngx_strlchr()` approach with bracket-aware parsing (same pattern as
`upstream/directives.c` lines 24–54):

```c
char *addr_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
ngx_memcpy(addr_copy, value[1].data, value[1].len);
addr_copy[value[1].len] = '\0';

if (addr_copy[0] == '[') {
    /* IPv6 literal [addr]:port */
    char *rb = strchr(addr_copy, ']');
    if (rb == NULL || *(rb + 1) != ':') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_proxy_upstream: invalid address \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    size_t hostlen = (size_t)(rb - addr_copy - 1);
    conf->proxy_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
    ngx_memcpy(conf->proxy_host.data, addr_copy + 1, hostlen);
    conf->proxy_host.data[hostlen] = '\0';
    conf->proxy_host.len = hostlen;
    conf->proxy_port = (ngx_int_t) strtol(rb + 2, &endp, 10);
} else {
    /* IPv4 or hostname:port */
    colon = strrchr(addr_copy, ':');
    // ... existing logic ...
}
```

### 7.4 P1 — Fix cache port extraction

**Files**: `src/fs/cache/thread.c` (line 125–126), `src/fs/cache/evict.c` (line 406–407)

```c
if (c->local_sockaddr->sa_family == AF_INET) {
    self_port = ntohs(((struct sockaddr_in *) c->local_sockaddr)->sin_port);
} else if (c->local_sockaddr->sa_family == AF_INET6) {
    self_port = ntohs(((struct sockaddr_in6 *) c->local_sockaddr)->sin6_port);
}
```

### 7.5 P2 — Fix stats query port extraction

**File**: `src/query/metadata.c` (lines 83–89)

Add `AF_INET6` branch alongside existing `AF_INET` check.

---

## 8. Comparison with Reference XRootD

| Behavior | Reference xrootd | nginx-xrootd current | Gap |
|----------|-----------------|---------------------|-----|
| Listen on dual-stack | Yes (`IPV6_V6ONLY` configurable) | Depends on nginx default + OS | Documented, testable |
| `kXR_locate` IPv6 response | Bracketed `[addr]:port` | `"localhost"` for IPv6 | **P1** |
| `kXR_redirect` IPv6 | Bracketed `[addr]:port` | Depends on config input | OK if config uses brackets |
| Outbound connect to IPv6 | Yes (`getaddrinfo`) | Yes (`getaddrinfo` in upstream/proxy) | None |
| Stats query IPv6 port | Correct port | Zero | **P2** |
| TPC to IPv6 source | Yes | Yes (already dual-stack) | None |
| SSRF guard IPv6 | Yes | Yes | None |
| Cache registration IPv6 | Correct port | Wrong port (bad cast) | **P1** |
| Proxy config IPv6 parse | N/A (not nginx module) | Fails on `[addr]:port` | **P1** |

---

## 9. Risk Assessment

| Risk | Likelihood | Impact | Severity |
|------|-----------|--------|----------|
| IPv6 clients cannot connect (upstream/proxy) | RESOLVED — dual-stack connect implemented | Was critical — blocked entire manager/proxy modes | Done |
| IPv6 clients get `"localhost"` from locate (P1) | High | High — locate response unusable | **P1** |
| Cache registration wrong port (P1) | Medium | High — manager routing broken for IPv6 | **P1** |
| Proxy config IPv6 parse fails (P1) | Medium | Medium — cannot configure IPv6 proxy | **P1** |
| Stats query port zero (P2) | Medium | Low — observability gap | **P2** |
| `inet_ntoa()` race condition | Low | Medium — potential log corruption | **P2** |
| Test infrastructure cannot run IPv6 tests | Low | Medium — cannot validate fixes | Process |

---

## 10. Testing Priority Order

1. **[RESOLVED] — Outbound IPv6 connects** (`upstream/start.c`, `proxy/connect_upstream.c`)
   Both call sites now resolve via `getaddrinfo(AF_UNSPEC)` and connect to IPv6
   backends. Remaining work is test coverage for these dual-stack paths.

2. **P1 — Fix and test kXR_locate IPv6 response** (`read/locate.c`)
   Without a parseable address in the locate response, IPv6 clients cannot
   discover the correct server address for redirects.

3. **P1 — Fix proxy_upstream config parsing** (`proxy/directives.c`)
   Enable configuration of IPv6 proxy upstreams.

4. **P1 — Fix cache port extraction** (`cache/thread.c`, `cache/evict.c`)
   Ensure manager-mode cache registration works on IPv6 listeners.

5. **P2 — Fix stats query port** (`query/metadata.c`)
   Observability fix — low user impact but important for monitoring.

6. **Integration testing** — End-to-end IPv6 paths for all three protocol layers
   (native XRootD, WebDAV, S3), manager mode, TPC, and cache.

7. **Cross-backend conformance** — Verify behavior matches reference xrootd
   on all IPv6 paths.

---

## 11. References

### RFCs and Standards

| RFC | Title | Relevance |
|-----|-------|-----------|
| **RFC 2553** | API for IP Version 6 | Deprecates `gethostbyname()`, introduces `getaddrinfo()` |
| **RFC 3493** | Basic Socket Interface Extensions for IPv6 | `getaddrinfo()`, `getnameinfo()`, `sockaddr_storage` |
| **RFC 3542** | IPv6 Socket Options | `IPV6_V6ONLY`, v4-mapped addresses |
| **RFC 3986** | URI Generic Syntax | §3.2.2: IPv6 literals in URIs MUST use brackets |
| **RFC 4038** | Application Protocol Documentation for IPv6 Transition | Guidance for IPv6-capable protocols |
| **RFC 5533** | DNS Resolution for Application Protocols | Server address format recommendations |
| **RFC 6724** | Default Address Selection for IPv6 | How clients choose between IPv4 and IPv6 |
| **RFC 8305** | Happy Eyeballs v2 | Better connectivity for dual-stack clients |

### XRootD / Protocol

| Source | Description |
|--------|-------------|
| Reference `xrootd` source | Dual-stack since v4.8+, configurable `IPV6_V6ONLY` |
| XRootD wire protocol spec | `kXR_locate` response is opaque string; clients expect brackets for IPv6 |
| Python `XRootD` client | IPv6-aware, parses bracketed addresses in redirects |
| C++ `XRootD` client (`libXRootD`) | IPv6-aware, uses `getaddrinfo` |

### nginx

| Source | Description |
|--------|-------------|
| nginx stream module docs | `listen` directive, `IPV6_V6ONLY` behavior by OS |
| nginx `ngx_sock_ntop()` | Dual-stack address formatter (internal API) |
| nginx `ngx_parse_url()` | Dual-stack URL resolver (used by CMS config) |
| nginx `c->addr_text` | Pre-formatted client address (dual-stack safe) |
