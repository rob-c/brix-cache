# Phase 36 — Full IPv6 Support Across All Protocols

**Status:** ✅ COMPLETE (Phases 0–4) — full IPv6 suite green (92 passed / 2 xfailed) against live `[::1]` instances · **Subsystem:** cross-cutting (`src/net/manager`, `src/response`, `src/net/cms`, `src/protocols/webdav`, `src/tpc`, plus the new `src/core/compat/host_format.c`) · **Build governance:** any new source file must be registered in the module's source list (the top-level `config` script — see the phase-35 build-governance note); editing `src/core/types/context.h` struct layout requires a **full rebuild** (mixed-ABI stale-object crash — see [[build_header_dep_mixed_abi]]).

> **Implementation status (this commit).** The bracket-on-emit fix is **implemented and builds clean** (full binary links; server-side IPv6 handshake confirmed over `[::1]`):
> - **New helper** `src/core/compat/host_format.{c,h}` (`xrootd_format_host`, `xrootd_format_host_port`, `xrootd_host_is_ipv6_literal`) — registered in `config`; standalone unit test green (bracket / IPv4 / hostname / already-bracketed / zone-id / overflow).
> - **Blockers:** `manager/registry.c:804` (`xrootd_srv_locate_all`), `response/control.c` (`xrootd_send_redirect` + `_tpc`).
> - **Majors:** `webdav/proxy_pool.c` (both Host branches), `webdav/proxy_config.c`, `tpc/launch.c` (URL rebuild).
> - **Minors:** `dashboard/api_admin.c` (strip `[]` on the admin host segment), `webdav/tpc_curl.c` (bracket the `CURLOPT_RESOLVE` host; `entry[]` widened to 512).
> - **Re-verified NOT gaps (no change):** buffer widening (`peer_ip[64]`/`pmark` are sufficient — avoids the full-rebuild); `ratelimit_keys.c` (internal bucket key, not a metric label — IPv6 already works); `macaroon_endpoint.c` (echoes the client's already-bracketed `Host:`); `s3/auth_sigv4_verify.c` (client-side canonicalization). Storage paths (`registry.c:256`, CMS capture, `tpc/parse.c`) were already correct.
> - **§7 IPv6 test suite — DONE & green.** 7 files (`tests/test_ipv6_{xrootd_stream,cms_redirect,webdav_xrdhttp,webdav_proxy,s3,tpc,admin_ratelimit_metrics}.py`), **92 passed / 2 xfailed / 0 failed** against the live `[::1]` instances; 30 gating tests prove the bracket fixes on the wire/header (registry-locate, redirect, proxy `Host:`, native-TPC URL, admin URI strip) + `locate.c` regression. Harness: `{BIND6_HOST}=[::1]` placeholder + `substitute_config`; `requires_ipv6_loopback` conftest fixture; six `[::1]` dedicated instances (`nginx_ipv6_*.conf`, ports 11240–11247) wired into `start_all_dedicated()`; `IPV6_*` ports in `settings.py`. **No product bugs** surfaced — every initial red was a test-side expectation (auth-model, PROPFIND href counting, `requests` `../` normalization, WebDAV-TPC config-disabled → 405). NB: PyXRootD mishandles `root://[::1]`, so all `root://`/CMS/native-TPC IPv6 tests use raw-wire sockets (§7.5).
> - **xfails (by design):** v6→v6 native-TPC pull is SSRF-denied (`allow_local=0` on `ipv6-stream`); WebDAV-TPC plaintext-egress short-circuit. The admin API on the IPv6 mgr is authorized via `xrootd_admin_allow ::1/128` (OR-mode, no secret file seeded by the harness).

---

## 1. Overview & Goals

### The finding

A verified per-subsystem audit (6 parallel auditors + synthesis, all findings re-checked against real code) shows the module is **partially IPv6-ready with one recurring root-cause defect**. The *socket and resolution layer* is already IPv6-clean; the gap is a single class of bug repeated at the protocol-emission sites:

> **IPv6 literal addresses are re-emitted into `host:port` wire strings and HTTP headers *without brackets*.** Because a bare IPv6 literal contains colons, `2001:db8::1:1094` is ambiguous/unparseable to a client expecting `host:port`.

The decisive evidence is an **asymmetry the codebase already exhibits**: the local kXR_locate path brackets correctly —

```c
/* src/read/locate.c:200  (AF_INET6 branch) — CORRECT */
loc_len = snprintf(loc_buf, sizeof(loc_buf), "S%c[%s]:%d", access_char, ipbuf, (int) port);
```

— but the registry/cluster locate path does not —

```c
/* src/net/manager/registry.c:804  (xrootd_srv_locate_all) — BARE, no brackets */
entry_len = snprintf(entry, sizeof(entry), "%sS%c%s:%u",
                     first ? "" : " ", for_write ? 'w' : 'r',
                     e->host, (unsigned int) e->port);
```

So the codebase **knows the right pattern; it just isn't applied at the registry, CMS, redirect, proxy, and TPC emission sites.**

### Goal

Make every protocol face fully IPv6-capable: a client connecting over IPv6 (or being redirected to an IPv6 data server, or proxied to an IPv6 backend) works identically to IPv4. Net result: **IPv6 works for clustering, redirects, and proxying — not just a standalone node.**

### Headline effort

| Milestone | Effort | What you get |
|---|---|---|
| **Blockers cleared** (helper + buffers + root:///CMS) | **~3–4 person-days** | IPv6 clustering, redirect, and locate work end-to-end |
| **Majors cleared** (WebDAV proxy + TPC) | **~2 person-days** | IPv6 backends/upstreams + native-TPC URL round-trip |
| **Minors + tests** (normalization sites + conformance) | **~2–3 person-days** | admin/rate-limit/SigV4/macaroon edges + the IPv6 test matrix |

One shared bracketing helper + two buffer widenings clears all blockers and majors; the rest is a handful of minor call sites.

### Non-goals

- **Listen-directive / config dual-stack work** — the audit found **no** defect here; `src/core/config/addr_parse.c` parses `[IPv6]:port` correctly and nginx `listen` already supports IPv6. Do **not** invent work in this area.
- **Outbound DNS / SSRF rework** — `src/core/compat/net_target.c` already uses `getaddrinfo(AF_UNSPEC)` + `sockaddr_storage` and classifies IPv4-mapped IPv6. Leave it.

---

## 2. The shared primitive (build this first)

Every blocker/major fix reuses one helper. New file `src/core/compat/host_format.c` (+ `.h`), registered in the module source list:

```c
/* Brackets an IPv6 literal host for use in a host:port wire/redirect/header string.
 * - IPv6 literal (inet_pton(AF_INET6) succeeds, or bare-colon host) -> "[host]:port"
 * - IPv4 / hostname / already-bracketed                            -> "host:port"
 * Returns bytes written (excl NUL), or 0 on overflow. */
size_t xrootd_format_host_port(const char *host, uint16_t port, char *out, size_t sz);

/* host-only variant for the kXR_redirect body (port is a separate 4-byte field). */
size_t xrootd_format_host(const char *host, char *out, size_t sz);

/* predicate: does this host string need bracketing? (colon present, not already '[') */
int    xrootd_host_is_ipv6_literal(const char *host);
```

Detection: `host[0] != '[' && strchr(host, ':') != NULL` (a hostname never contains a colon; an IPv4 dotted-quad never does). Confirm with `inet_pton(AF_INET6)` when stripping/validating. Co-locate near the existing address helpers; reuse, don't duplicate, the bracket logic already proven in `read/locate.c` and `config/addr_parse.c`.

---

## 3. Gap inventory (by severity)

### A. Wire `host:port` literal bracketing — **BLOCKER** (root://, CMS)

| Site | Defect | Fix |
|---|---|---|
| `src/net/manager/registry.c:804` (`xrootd_srv_locate_all`) | `"%sS%c%s:%u"` with bare `e->host` → `Sr::1:1094` | format host via helper before the `S%c…` assembly |
| `src/net/manager/registry.c:256` (`xrootd_srv_register`) | host stored bare from `ngx_sock_ntop` | **decide once:** bracket-on-emit (preferred — keep store canonical/bare) *or* bracket-on-store |
| `src/net/cms/server_recv.c` + `src/net/cms/server_handler.c:57` | inbound data-server peer captured bare, reused in locate | same emit-time fix on the CMS-registered host |
| `src/response/control.c:71` (`xrootd_send_redirect`) | kXR_redirect body `[port:4B][host]` passes `host` verbatim | bracket an IPv6 literal in the host field via `xrootd_format_host()` (port stays the separate 4-byte field) |

> **Severity reconciliation:** for a single standalone node this is *major* (the local `locate.c` path already brackets); for the **cluster/redirect path it is a blocker** — IPv6 clustering does not function without it. Recommend **bracket-on-emit** so the registry keeps a canonical bare address and all emitters share the one helper.

### B. WebDAV / proxy `Host:` header — **MAJOR** (WebDAV proxy)

| Site | Defect | Fix |
|---|---|---|
| `src/protocols/webdav/proxy_pool.c:167` (`proxy_pool_resolve`) | `"%V:%d%Z"` with bare host → `Host: 2001:db8::1:8080` | helper; also the default-port branch (`out->host` copy) needs bracketing for the bare-IPv6 case |
| `src/protocols/webdav/proxy_config.c:76` (`webdav_proxy_add_url`) | same defect at config-parse time | helper |

### C. Native-TPC URL rebuild — **MAJOR** (TPC)

| Site | Defect | Fix |
|---|---|---|
| `src/tpc/parse.c:169` → `src/tpc/launch.c:180` (`tpc_register_stream_transfer`) | parse *strips* brackets into `src_host`, launch rebuilds `root://%s:%ui%s` *without* re-bracketing | re-bracket at format time (or carry an `is_ipv6` flag / `sockaddr_storage`) |

Also a **security-negative** to cover: confirm the re-bracketed `root://[::ffff:127.0.0.1]:1094` form is still rejected by the SSRF/local-deny policy (`tpc/connect.c` per-candidate check is already correct; verify the round-trip doesn't bypass it).

### D. Address buffer / struct sizing — **MINOR** (cheap; do regardless)

| Site | Fix |
|---|---|
| `src/core/types/context.h:141` `peer_ip[64]` | widen to `INET6_ADDRSTRLEN + 16` (brackets + link-local `%zone` scope-id margin). ⚠️ struct-layout edit → **full rebuild** |
| `src/observability/pmark/pmark.h:118-119` `src_ip[64]`/`dst_ip[64]` | widen to `INET6_ADDRSTRLEN + 16` (link-local `fe80::1%ifname`) |
| `src/net/manager/registry.h:28` `host[256]`, `src/net/manager/redir_cache.c:40` `host[128]` | sufficient; **document the IPv6+brackets budget** and keep bounds-checked writes |

### E. Normalization / parsing edges — **MINOR**

| Site | Defect | Fix |
|---|---|---|
| `src/observability/dashboard/api_admin.c:395` (`admin_parse_server_uri`) | splits URI tail on `/` only; a `[2001:db8::1]` segment survives but brackets aren't stripped for registry host-matching | bracket-detect/strip the host segment before comparing to registry entries |
| `src/net/ratelimit/ratelimit_keys.c:52,60,68,73` | `"ip:%s"` with bare `peer_ip` → colon-bearing key | bracket or use a non-colon separator; **keep raw IP out of low-cardinality metric labels** (invariant #8) |
| `src/protocols/webdav/macaroon_endpoint.c:416` | Location URL from client `Host:` without IPv6 validation/bracketing | normalize/bracket |
| `src/protocols/s3/auth_sigv4_verify.c:312` | SigV4 canonical request uses raw `Host`; `::1` vs expanded forms break the signature | defensive Host normalization (largely client responsibility — document) |
| `src/protocols/webdav/tpc_curl.c:77` | `CURLOPT_RESOLVE` entry format | likely OK (`getnameinfo(NI_NUMERICHOST)` output is bracketed) — **verify end-to-end** |

---

## 4. Per-protocol status

| Protocol | Status | Key need |
|---|---|---|
| **root:// stream** | standalone OK, redirect broken | bracket in `control.c` + registry path |
| **CMS / clustering** | **blocked** | bracket registry host (`registry.c:804/256`, `cms/server_*`) |
| **WebDAV / XrdHttp** | major gap | bracket proxy `Host:` (`proxy_pool.c`, `proxy_config.c`) |
| **S3** | mostly OK | SigV4 Host normalization edge only |
| **TPC (native + WebDAV)** | major gap | re-bracket URL rebuild (`launch.c:180`); parse already correct |
| **proxy / mirror / cache** | mostly OK | covered by WebDAV proxy fix; transports use `sockaddr_storage` |
| **dashboard / admin / metrics** | minor–major | bracket-aware admin host parse; sanitize rate-limit IP key |

---

## 5. Already correct — do not touch

`src/core/compat/net_target.c` (AF_UNSPEC + `[IPv6]:port` parse + SSRF v4-mapped classification, lines 30-133/242-278/387-410), `src/core/config/addr_parse.c:99-124` (bracket parsing), `src/connection/handler.c:50-68` + `disconnect.c:133-143` (AF_INET6 detection + per-version metrics), `src/auth/authz/authdb.c:285-344` (IPv6 CIDR matching), `src/read/locate.c:182-204` (local locate brackets correctly), `src/auth/unix/auth.c` + `src/auth/krb5/auth.c:57-81` (`::1` / ADDRTYPE_INET6), `src/protocols/webdav/proxy_pool.h:40` + `src/net/mirror/mirror.h:116` (`sockaddr_storage`), `src/tpc/connect.c:107-149` (AF_UNSPEC per-candidate policy), inbound stats/metrics (`webdav/access.c`, `webdav/xrdhttp_stats.c`, `query/metadata.c`, `cache/evict_policy.c`).

---

## 6. Implementation order

1. **Shared helper** — `src/core/compat/host_format.c` + `.h`; register in the module source list; unit-cover the bracket/no-bracket/already-bracketed/IPv4/hostname cases.
2. **Buffer widening** — `context.h:141`, `pmark.h:118-119` → `INET6_ADDRSTRLEN + 16` (full rebuild after the `context.h` edit).
3. **Blockers (root:// + CMS)** — apply the helper at `registry.c:804`, `registry.c:256`, `control.c:71`, `cms/server_handler.c:57` + `cms/server_recv.c`. Choose **bracket-on-emit**.
4. **Majors (WebDAV proxy + TPC)** — `proxy_pool.c:167`, `proxy_config.c:76`, `tpc/launch.c:180`; verify `tpc_curl.c:77`.
5. **Minors** — `api_admin.c:395`, `ratelimit_keys.c`, `macaroon_endpoint.c:416`, `s3/auth_sigv4_verify.c:312` (document).

## 7. IPv6 Test Plan

This section replaces and expands the prior brief Section 7. It defines the full IPv6 conformance suite: a shared `[::1]` harness, five per-protocol test files, and an explicit acceptance-vs-regression split mapped to the §3 fix sites.

The suite is built on the existing **pre-started dedicated-instance pattern** (`start_dedicated_nginx "<name>" "nginx_<name>.conf" "<port>"` in `start_all_dedicated()`, `tests/manage_test_servers.sh`; `substitute_config` fills `{PORT}{DATA_DIR}{LOG_DIR}{TMP_DIR}{CA_CERT}{BIND_HOST}{S3_PORT}`; data root `TEST_ROOT/data-<name>`; `settings.py` exposes `<NAME>_PORT` + `<NAME>_DATA_ROOT`). Tests connect and `pytest.skip` if the instance is down, exactly like `tests/test_open_flags_lifecycle.py::wr_stack` (`_reachable()` → `pytest.skip`) and `tests/test_vo_acl.py::vo_nginx`.

### 7.1 Shared IPv6 test infrastructure

#### 7.1.1 The `{BIND6_HOST}` placeholder

`substitute_config()` defaults `{BIND_HOST}` to **`127.0.0.1`** (`manage_test_servers.sh:256`), so it cannot be reused for IPv6 — nginx requires the bracket form `listen [::1]:{PORT};`. Add one new placeholder:

```sh
# tests/manage_test_servers.sh — substitute_config()
: "${BIND6_HOST:=[::1]}"
...
-e "s|{BIND6_HOST}|${BIND6_HOST}|g" \
```

IPv6-only configs use `listen {BIND6_HOST}:{PORT};`; dual-stack configs use **both** `listen {BIND_HOST}:{PORT};` and `listen {BIND6_HOST}:{PORT};`. This keeps every existing IPv4 template byte-identical (the new placeholder is simply absent from them) and lets one template serve both families by swapping `BIND6_HOST`/`BIND_HOST` per dedicated-instance start.

#### 7.1.2 Reusable skip helper (`tests/conftest.py`)

A single session-scoped helper gates every IPv6 test so the suite is a clean no-op on hosts without `::1` (WSL2 without the IPv6 module, IPv6-disabled kernels, containers, IPv6-off EC2):

```python
# tests/conftest.py
import socket, pytest

def _ipv6_loopback_available():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0)); s.close()
        return True
    except OSError:
        return False

_HAVE_IPV6 = _ipv6_loopback_available()

@pytest.fixture(scope="session")
def requires_ipv6_loopback():
    if not _HAVE_IPV6:
        pytest.skip("IPv6 loopback ::1 not available on this host")

def reachable6(port, timeout=2.0):
    """[::1]:port up? mirrors test_open_flags_lifecycle._reachable for AF_INET6."""
    try:
        socket.create_connection(("::1", port), timeout=timeout).close()
        return True
    except OSError:
        return False
```

Each IPv6 fixture composes `requires_ipv6_loopback` **then** `reachable6(<PORT>)` → `pytest.skip` if the dedicated instance is not up. No instance-down failure ever reddens the suite.

#### 7.1.3 New dedicated instances (consolidated)

All registered in `start_all_dedicated()` and `settings.py`. The ports below are a **proposal — reconcile against the live allocation before wiring** (`grep -oE ':-[0-9]{4,5}' tests/manage_test_servers.sh` + the test-server-migration backlog): some entries reuse existing numbers (`9001` is the shared S3 port; `12990/12991` are claimed by the `dropin` migration pair). An IPv6 `listen [::1]:9001;` *can* coexist with the IPv4 `0.0.0.0:9001` listener (different address family, no kernel conflict), but a **same-family** clash must be reassigned. `bash -n` + a `start-all` bind probe surfaces any conflict at startup, not as an opaque test failure.

| Instance name | `_PORT` (settings var) | Protocol / role | `listen` directive(s) | Config template |
|---|---|---|---|---|
| `ipv6-only` | `IPV6_ONLY_PORT` = 11170 | root:// stream, IPv6-only | `listen [::1]:11170;` | `nginx_ipv6_only.conf` |
| `ipv6-dual` | `IPV6_DUAL_PORT` = 11171 | root:// stream, dual-stack | `listen 127.0.0.1:11171; listen [::1]:11171;` | `nginx_ipv6_dual.conf` |
| `cluster-redir-ipv6` | `CLUSTER_IPV6_REDIR_PORT` / `CLUSTER_IPV6_CMS_PORT` | CMS redirector (manager+cms), IPv6 | `listen [::1]:{REDIR}; listen [::1]:{CMS};` | `nginx_cluster_redir.conf` (`{BIND_HOST}=[::1]`) |
| `cluster-ds-ipv6` | `CLUSTER_IPV6_DS_PORT` | CMS data server, IPv6 | `listen [::1]:{DS};` | `nginx_cluster_ds.conf` (`{BIND_HOST}=[::1]`) |
| `cluster-ds-dual` | `CLUSTER_DS_DUAL_PORT` / `CLUSTER_DS_DUAL_IPV6_PORT` | CMS data server, dual-stack | `listen 127.0.0.1:{V4}; listen [::1]:{V6};` | `nginx_cluster_ds.conf` (templated twice) |
| `webdav_ipv6` | `NGINX_WEBDAV_IPV6_PORT` = 13290 | WebDAV / XrdHttp, IPv6 | `listen [::1]:13290;` | `nginx_webdav_ipv6.conf` |
| `webdav-dualstack` | `NGINX_WEBDAV_DUALSTACK_PORT` | WebDAV dual-stack (regression) | `listen 127.0.0.1:{P}; listen [::1]:{P};` | `nginx_webdav_dualstack.conf` |
| `webdav_v6_upstream` | `WEBDAV_V6_UPSTREAM_PORT` = 12991 | proxy backend origin, IPv6 | `listen [::1]:12991;` | `nginx_webdav_v6_upstream.conf` |
| `webdav_v6_proxy` | `WEBDAV_V6_PROXY_PORT` = 12992 | WebDAV proxy → IPv6 upstream | `listen [::1]:12992;` (`proxy_upstream https://[::1]:12991`) | `nginx_webdav_v6_proxy.conf` |
| `webdav_v6_mirror` | `WEBDAV_V6_MIRROR_PORT` = 12993 / `WEBDAV_V6_MIRROR_UP_PORT` = 12994 | traffic-mirror front + IPv6 upstream | `listen [::1]:12993;` (`stream_mirror_url [::1]:12994`) | `nginx_webdav_v6_mirror.conf` |
| `webdav-dualstack-proxy` | `WEBDAV_DUALSTACK_PROXY_PORT` = 12995 | proxy dual-stack | `listen 127.0.0.1:12995; listen [::1]:12995;` | `nginx_webdav_v6_proxy.conf` (dual) |
| `s3-ipv6` | `S3_IPV6_PORT` = 9001 | S3 REST, IPv6 | `listen [::1]:9001;` | `nginx_s3-ipv6.conf` |
| `s3-dual` | `S3_DUAL_PORT` = 9002 | S3 dual-stack | `listen 127.0.0.1:9002; listen [::1]:9002;` | `nginx_s3-dual-stack.conf` |
| `tpc-ipv6-native` | `TPC_IPV6_NATIVE_PORT` = 11185 | native root:// TPC dest, IPv6 | `listen [::1]:11185;` | `nginx_tpc_ipv6_native.conf` |
| `tpc-ipv6-webdav` | `TPC_IPV6_WEBDAV_PORT` = 11186 | WebDAV HTTP-TPC dest (HTTPS), IPv6 | `listen [::1]:11186;` | `nginx_tpc_ipv6_webdav.conf` |
| `tpc-ipv6-ref` | `TPC_IPV6_REF_PORT` = 11187 | TPC source/reference, IPv6 | `listen [::1]:11187;` | `nginx_tpc_ipv6_reference.conf` |
| `ipv6-admin` | `NGINX_IPV6_ADMIN_PORT` = 21600 | dashboard/admin/ratelimit/metrics, IPv6 | `listen [::1]:21600;` | `nginx_ipv6_admin.conf` |
| `ipv4-admin` | `NGINX_IPV4_ADMIN_PORT` = 21601 | admin dual-stack control (regression) | `listen 127.0.0.1:21601;` | `nginx_ipv4_admin.conf` |

Each `settings.py` entry follows the established `<NAME>_PORT` + `<NAME>_DATA_ROOT = os.path.join(TEST_ROOT, "data-<name>")` convention, e.g.:

```python
IPV6_ONLY_PORT      = int(os.environ.get("TEST_IPV6_ONLY_PORT", "11170"))
IPV6_ONLY_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-only")
S3_IPV6_PORT        = int(os.environ.get("TEST_S3_IPV6_PORT", "9001"))
S3_IPV6_DATA_ROOT   = os.path.join(TEST_ROOT, "data-s3-ipv6")
```

Data dirs are seeded by the conftest session setup exactly like other instances (`test.txt` = `hello from nginx-xrootd`, 24 bytes; `random.bin`; bucket subdirs for S3).

### 7.2 Per-protocol test files

#### 7.2.1 `tests/test_ipv6_xrootd_stream.py` — root:// XRootD stream over IPv6

Covers raw-wire handshake/login, scalar/vector/pgread reads, write, stat/statx, dirlist, qcksum, mkdir/mv/rm, and the local-locate bracketing regression, all over `root://[::1]:11170`. Plus dual-stack (`:11171`), the redirect/registry/TPC-URL **emit** gating cases, the `AF_INET6` peer-addr capture path, concurrency isolation, and link-local rejection.

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_ipv6_connect_handshake_login` | success | ClientInitHandShake accepted; kXR_protocol → kXR_ok; kXR_login → valid session id | — |
| `test_ipv6_open_read_scalar_byte_exact` | success | open → valid handle; `read(24)` == `hello from nginx-xrootd` | — |
| `test_ipv6_open_read_vector_byte_exact` | success | `vector_read()` byte-exact vs `data-ipv6-only/random.bin` | — |
| `test_ipv6_pgread_wire_crc32c_conformance` | success | kXR_pgread (3030) body: per-4096 page CRC32c recomputes; short tail correct; zero-read ok | — |
| `test_ipv6_write_open_new_byte_exact` | success | `open(DELETE)`+`write(64KiB)`; file on disk; md5 matches | — |
| `test_ipv6_stat_statx` | success | `stat().size==24`, mtime present; `File.stat(FORCE)` refreshes | — |
| `test_ipv6_dirlist` | success | dirlist lists `test.txt` + `test_ipv6_write.bin` with stat info | — |
| `test_ipv6_qcksum` | success | `query(CHECKSUM)` adler32 == `zlib.adler32(test.txt)` | — |
| `test_ipv6_mkdir_mv_rm` | success | mkdir/mv/rm all succeed; mv visible in dirlist | — |
| `test_ipv6_locate_local_brackets_regression` | regression | locate body has `Sr[::1]:11170`, **not** bare `Sr::1:11170` (`read/locate.c` already brackets) | — |
| `test_ipv6_dual_stack_ipv4_client` | dual-stack | IPv4 client to `:11171` works identically to IPv4-only | — |
| `test_ipv6_dual_stack_ipv6_client` | dual-stack | IPv6 client to same instance; both families serve same files byte-exact | — |
| `test_ipv6_redirect_bracket_format_gating` | wire-bracketing | kXR_redirect body: 4-byte BE port + `[::1]` host, not bare `::1` (`response/control.c:71`) | **YES** |
| `test_ipv6_registry_locate_bracket_format_gating` | wire-bracketing | registry locate body has `Sr[::1]:1094` entries, not bare (`manager/registry.c:804`) | **YES** |
| `test_ipv6_tpc_url_round_trip_bracket_gating` | wire-bracketing | TPC `root://[::1]:port//path` survives parse→rebuild re-bracketed (`tpc/launch.c:180`) | **YES** |
| `test_ipv6_security_neg_tpc_ssrf_loopback_blocked` | security-neg | `[::ffff:127.0.0.1]` and `[::1]` rejected as local under default deny (`tpc/connect.c`) | **YES** |
| `test_ipv6_handshake_wire_ipv6_peer_addr` | success | `c->sockaddr` family `AF_INET6`; `peer_ip` (widened) holds bare `::1` (`connection/handler.c`) | — |
| `test_ipv6_concurrent_streams_isolation` | success | multiple streams independent; closing one leaves others; all byte-exact | — |
| `test_ipv6_link_local_rejection` | success | `fe80::1` listen rejected/best-effort; link-local unreachable across loopback | — |

#### 7.2.2 `tests/test_ipv6_cms_redirect.py` — CMS clustering + redirect to IPv6 data servers

Covers locate/open redirect bodies (host must be bracketed), follow-the-redirect read, dual-stack cross-family redirects, multi-server selection, three-tier topology, `redir_cache`/tried-list regressions, CMS LOGIN registration of an IPv6 DS, and graceful skips.

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_ipv6_cluster_locate_returns_redirect` | success | locate → kXR_redirect (4004); port == DS port; host `[::1]` bracketed | **YES** |
| `test_ipv6_cluster_locate_host_is_bracketed` | wire-bracketing | redirect host == `[::1]` (matches `[0-9a-f:]+` bracketed), not bare `::1` | **YES** |
| `test_ipv6_cluster_open_returns_redirect` | success | open(read) → kXR_redirect to DS port; host bracketed | **YES** |
| `test_ipv6_cluster_client_follows_redirect_and_reads` | success | client follows to `[::1]:DS`, reads 256B byte-exact vs IPv4 control | **YES** |
| `test_dual_stack_ipv4_client_to_ipv6_ds_redirect` | dual-stack | IPv4 client → dual redirector → `[::1]:port` bracketed; byte-exact follow | **YES** |
| `test_dual_stack_ipv6_to_ipv4_ds_redirect` | dual-stack | IPv6 client → IPv4 DS; host `127.0.0.1` (no brackets); follow byte-exact | — |
| `test_ipv6_registry_locate_body_all_entries_bracketed` | wire-bracketing | multi-server CMS body: every entry `Sr[::1]:port`, space-separated, parseable | **YES** |
| `test_ipv6_cms_login_registers_data_server` | success | raw CMS LOGIN with dPort `[::1]:DS`; later locate redirects (entry accepted) | — |
| `test_ipv6_tried_cache_redirect_loop_avoidance` | regression | tried/triedrc second attempt → kXR_NotFound (3011), no loop | — |
| `test_ipv6_redir_cache_stores_bracketed_host` | regression | second locate served from `redir_cache`; host stays bracketed; no miss | — |
| `test_ipv6_cluster_multi_server_selection` | success | redirect to one of two valid `[::1]:portN`; load-balances; no parse error | **YES** |
| `test_ipv6_cms_gone_deregistration` | regression | pre-GONE locate redirects; post-`kYR_GONE` path no longer redirects | — |
| `test_ipv6_cluster_nonexistent_returns_not_found` | regression | nonexistent → kXR_NotFound (3011), no loop; tried-exhaustion works w/ IPv6 | — |
| `test_bare_ipv6_literal_in_redirect_rejected_or_normalized` | wire-bracketing | injected bare `::1:1094` body → client rejects/normalizes, never mis-parses | **YES** |
| `test_ipv6_cluster_stat_redirects_identically_to_open` | regression | stat and open both → kXR_redirect to same `[::1]:port` | — |
| `test_ipv6_three_tier_topology_redirects_bracketed` | success | meta→sub→leaf, every hop bracketed `[ipv6]:port`; client reaches leaf | **YES** |
| `test_ipv6_manager_map_redirect_host_bracketed` | wire-bracketing | static `xrootd_manager_map` → redirect body `[::1]:port`, not bare | **YES** |
| `test_ipv6_no_ipv6_loopback_skip_gracefully` | regression | no `::1` host → `pytest.skip`; suite does not fail | — |
| `test_ipv6_ds_not_up_skip_gracefully` | regression | IPv6 instance down → port probe → `pytest.skip`; suite continues | — |

#### 7.2.3 `tests/test_ipv6_webdav_xrdhttp.py` — WebDAV / XrdHttp over IPv6

Covers the full method surface (OPTIONS/PUT/GET/HEAD/Range/DELETE/MKCOL/PROPFIND/MOVE/COPY/LOCK/UNLOCK), XrdHttp proto-detection / digest / checksum / multipart / stats, macaroon issuance, proxy `Host:`, native-TPC URL round-trip, SSRF negatives, and the authdb IPv6-peer regression, all on `https://[::1]:13290`.

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_ipv6_webdav_options_returns_200` | success | 200; `Allow` has PROPFIND; `DAV:` header present | — |
| `test_ipv6_webdav_put_new_file` | success | 201; file byte-exact on disk | — |
| `test_ipv6_webdav_put_large_file` | success | 201/200; 2MB chunked body byte-exact | — |
| `test_ipv6_webdav_get_existing_file` | success | 200; body byte-exact | — |
| `test_ipv6_webdav_head_returns_content_length` | success | 200; `Content-Length` == file size | — |
| `test_ipv6_webdav_range_request` | success | 206; exactly 10 bytes at correct offset | — |
| `test_ipv6_webdav_delete_file` | success | 204; file removed | — |
| `test_ipv6_webdav_mkcol_directory` | success | 201; directory exists | — |
| `test_ipv6_webdav_propfind_depth_0` | wire-bracketing | 207; `<D:href>` relative, no host literal | **YES** |
| `test_ipv6_webdav_propfind_depth_1` | wire-bracketing | 207; 4 `<D:response>`; each href relative, no IPv6 host | **YES** |
| `test_ipv6_webdav_propfind_href_no_host_literal` | wire-bracketing | no href contains `::1` / `[::1]` / `[::` | **YES** |
| `test_ipv6_webdav_propfind_allprop_properties` | success | 207; getcontentlength/getlastmodified/getetag/resourcetype present | — |
| `test_ipv6_webdav_propfind_prop_request` | success | 207; only requested getcontentlength returned | — |
| `test_ipv6_webdav_move_destination_header_bracketed` | wire-bracketing | 201/204; src gone, dst exists; reemitted Destination bracketed | **YES** |
| `test_ipv6_webdav_copy_destination_header` | wire-bracketing | 201/204; src kept, dst copied; no host corruption | **YES** |
| `test_ipv6_webdav_lock_on_ipv6` | success | 201; `Lock-Token: opaquelocktoken:` usable in UNLOCK | — |
| `test_ipv6_webdav_lock_propfind_shows_lockdiscovery` | success | 207; lockdiscovery + supportedlock + token | — |
| `test_ipv6_webdav_unlock_with_token` | success | LOCK 201; UNLOCK 204; re-LOCK succeeds | — |
| `test_ipv6_webdav_propfind_xml_escaping` | success | 207; valid XML; `& < >` → `&amp; &lt; &gt;` | — |
| `test_ipv6_webdav_token_auth_optional` | success | 200 without Authorization | — |
| `test_ipv6_webdav_token_auth_with_bearer` | success | 200 with valid Bearer | — |
| `test_ipv6_xrdhttp_proto_detection` | success | 200; `X-Xrootd-Requuid` echoed; `X-Xrootd-Status: 0` | — |
| `test_ipv6_xrdhttp_digest_sha256` | success | 200; `Digest: sha256=` matches file hash | — |
| `test_ipv6_xrdhttp_checksum_query_param` | success | 200; `Digest: adler32=` matches | — |
| `test_ipv6_xrdhttp_multipart_range` | success | 206; multipart/byteranges; both sections present | — |
| `test_ipv6_xrdhttp_stats_endpoint` | success | 200; text/xml; `<statistics>`, `xrootd`+`http` blocks | — |
| `test_ipv6_macaroon_endpoint_location_url` | wire-bracketing | 200; JSON token; Location (if any) usable at `[::1]:PORT` | **YES** |
| `test_ipv6_macaroon_token_roundtrip` | wire-bracketing | macaroon decodes; TPC Credential pull to `[::1]` succeeds bracketed | **YES** |
| `test_ipv6_proxy_host_header_not_bare` | wire-bracketing | proxy `Host:` to backend is `[::1]:PORT`, never bare | **YES** |
| `test_ipv6_tpc_url_roundtrip_bracketed` | wire-bracketing | parse host `::1` → rebuild `root://[::1]:PORT/...` | **YES** |
| `test_ipv6_tpc_ssrf_policy_still_blocks_localhost` | security-neg | `root://[::1]` source under local-deny → 403/409; no connect | **YES** |
| `test_ipv6_tpc_ssrf_ipv4_mapped_still_blocked` | security-neg | `root://[::ffff:127.0.0.1]` → 403/409; classified loopback | **YES** |
| `test_ipv6_webdav_authdb_ipv6_peer` | regression | authdb `p ::1/128 /hostcidr r` → 200 (already correct) | — |
| `test_ipv6_dual_stack_ipv4_client_to_ipv6_backend` | dual-stack | IPv4 client → dual nginx → `[::1]` backend; 200; bracketed re-emit | **YES** |
| `test_ipv6_webdav_missing_file_returns_404` | success | 404 | — |
| `test_ipv6_propfind_depth_infinity` | success | 207; all descendants; hrefs relative | — |
| `test_ipv6_path_traversal_rejected` | success | `/../etc/passwd` → 400/403/404; IPv6 does not bypass path checks | — |

#### 7.2.4 `tests/test_ipv6_webdav_proxy.py` — WebDAV proxy + traffic mirror with IPv6 backends

Focused on the proxy/mirror `Host:`-header re-emission (`proxy_pool.c:167`, `proxy_config.c:76`) and the default-port bracketing branch, plus cross-family proxying, dual-stack, divergence logging, and concurrency. Uses the `webdav_v6_proxy` → `webdav_v6_upstream` and `webdav_v6_mirror` pairs.

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_ipv6_proxy_get_small_file` | wire-bracketing | 200 byte-exact; backend `Host: [::1]:12991`, not bare | **YES** |
| `test_ipv6_proxy_put_small_file` | wire-bracketing | 201; file on upstream; `Host: [::1]:12991` | **YES** |
| `test_ipv6_proxy_get_large_file` | wire-bracketing | 200; 256KB byte-exact; bracketed Host on all upstream reqs | **YES** |
| `test_ipv6_proxy_host_header_dual_port_default` | wire-bracketing | default port (443) → `Host: [::1]` (no port); non-default keeps `[::1]:port` | **YES** |
| `test_ipv6_proxy_host_header_non_default_port` | wire-bracketing | `Host: [::1]:9999` (port after bracket) | **YES** |
| `test_ipv6_mirror_get_from_upstream` | success | 200; content matches upstream; mirror reaches `[::1]:12994` | — |
| `test_ipv6_mirror_put_to_upstream` | success | file on front; shadow PUT to upstream; `Host: [::1]` | — |
| `test_ipv6_proxy_config_parse_brackets` | wire-bracketing | config `https://[::1]:12991` loads; first req `Host: [::1]:12991` | **YES** |
| `test_ipv6_proxy_ipv4_upstream_mixed` | success | IPv6 proxy → IPv4 upstream; `Host: 127.0.0.1:12990` (no brackets) | — |
| `test_dualstack_proxy_ipv4_client` | regression | IPv4 client on dual proxy; upstream Host not bracketed | — |
| `test_dualstack_proxy_ipv6_client` | success | IPv6 client on dual proxy; upstream Host bracketed `[::1]` | — |
| `test_ipv6_proxy_redirect_follow_bracket` | success | upstream redirect re-emitted with bracketed Location; client follows | — |
| `test_ipv6_proxy_delete_file` | success | 204/200; file gone; `Host: [::1]:12991` | — |
| `test_ipv6_proxy_lock_unlock` | success | LOCK/UNLOCK 200; `Host: [::1]:12991` both | — |
| `test_ipv6_proxy_propfind` | success | 207; props match; `Host: [::1]:12991` | — |
| `test_ipv6_mirror_divergence_log_bracket` | regression | divergence log line carries formatted `[::1]`, not bare | — |
| `test_ipv6_proxy_no_upstream_ready_error` | success | dead `[::1]:DEAD` → 502/503/kXR_error; no hang, no core | — |
| `test_ipv6_client_connect_IPv6_listen_success` | success | raw connect `[::1]:12992`; GET 200 correct content | — |
| `test_ipv6_proxy_concurrent_clients` | regression | 3 concurrent IPv6 GETs distinct content; `Host: [::1]` all | — |

#### 7.2.5 `tests/test_ipv6_s3.py` — S3 object storage over IPv6

Covers PUT/GET/HEAD/list/delete/range/copy/multipart/CORS over `[::1]:9001`, SigV4 header + presigned auth with the IPv6 canonical `Host`, the dual-stack cross-family redirect gate, and the SSRF/timeskew/bad-sig/traversal negatives. The canonical-Host tests verify the server reads `r->headers_in.host` verbatim (`s3/auth_sigv4_verify.c:312`).

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_s3_ipv6_anonymous_put_and_get` | success | PUT 200; GET 200 byte-exact | — |
| `test_s3_ipv6_head_object` | success | 200; Content-Length + ETag correct | — |
| `test_s3_ipv6_list_objects_v2` | success | 200; XML parses; keys present | — |
| `test_s3_ipv6_delete_object` | success | DELETE 204; GET 404 NoSuchKey | — |
| `test_s3_ipv6_range_get` | success | 206; Content-Range; bytes match | — |
| `test_s3_ipv6_copy_object` | success | 200; CopyObjectResult; dst byte-exact | — |
| `test_s3_ipv6_multipart_upload_full_cycle` | success | Initiate/UploadPart×3/Complete 200; concat in order | — |
| `test_s3_ipv6_sigv4_header_auth` | success | signature validates with canonical `Host: [::1]:port`; GET 200 | — |
| `test_s3_ipv6_sigv4_host_normalization` | success | server signs against client `[::1]:port` Host verbatim; auth ok | — |
| `test_s3_ipv6_presigned_url` | success | query-SigV4 on `https://[::1]:port/...` validates; 200 | — |
| `test_s3_ipv6_delete_objects_batch` | success | POST `?delete` 200; DeleteResult; each GET 404 | — |
| `test_s3_ipv6_options_cors_preflight` | success | 200; Allow has GET/HEAD/PUT/DELETE/POST/OPTIONS | — |
| `test_s3_dual_stack_ipv4_client_to_ipv6_redirect` | dual-stack | IPv4 → redirect target `[::1]:S3_DUAL_PORT`; client follows; 200 | **YES** |
| `test_s3_ipv6_get_missing_404_xml` | regression | 404; XML `<Code>NoSuchKey</Code>` | — |
| `test_s3_ipv6_put_zero_byte_object` | regression | PUT 200; GET 200 0-byte | — |
| `test_s3_ipv6_path_traversal_rejected` | security-neg | `../` key → 403/404, never 200/500; no escape | — |
| `test_s3_ipv6_sigv4_bad_signature_rejected` | security-neg | bit-flipped sig → 403 SignatureDoesNotMatch | — |
| `test_s3_ipv6_sigv4_future_timestamp_rejected` | security-neg | +1h date → 403 RequestTimeTooSkewed | — |
| `test_s3_ipv6_sigv4_expired_presigned_rejected` | security-neg | expired presign → 403 | — |
| `test_s3_ipv6_host_header_required_sigv4` | regression | Host omitted from SignedHeaders → 400/403 | — |
| `test_s3_ipv6_multipart_abort` | regression | abort 204; later part/complete → 404 NoSuchUpload | — |
| `test_s3_ipv6_sigv4_canonical_uri_encoding` | regression | special-char key RFC3986-encoded; sig validates; object retrieved | — |

#### 7.2.6 `tests/test_ipv6_tpc.py` — Native + WebDAV TPC with IPv6 endpoints

Covers native `--tpc only/first` v6→v6, cross-stack v4↔v6, the registry/display-URL re-bracket (`launch.c:180`), WebDAV HTTP-TPC pull/push with bracketed `Host:`, SSRF policy across `[::1]` and `[::ffff:127.0.0.1]` (both allow and deny), and the already-correct `AF_UNSPEC` outbound / timeout / origin-id regressions (`tpc/connect.c:107-149`).

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_native_tpc_ipv6_query_config` | success | `query config tpc` on `[::1]` returns tpc present | — |
| `test_native_tpc_ipv6_local_v6_to_v6` | wire-bracketing | `--tpc only` `[::1]`→`[::1]` byte-exact (launch rebuild brackets) | **YES** |
| `test_native_tpc_ipv6_local_v6_to_v6_first` | wire-bracketing | `--tpc first` `[::1]`→`[::1]` byte-exact | **YES** |
| `test_native_tpc_ipv6_register_stream_transfer` | wire-bracketing | registry URL shows `root://[::1]:port/path`, no bare `::1:port` | **YES** |
| `test_webdav_tpc_ipv6_http_copy_pull` | wire-bracketing | COPY pull `Source: https://[::1]:port`; 201/202 byte-exact; outbound `Host: [::1]:port` | **YES** |
| `test_webdav_tpc_ipv6_http_copy_push` | wire-bracketing | COPY push `Destination: https://[::1]:port`; 201/202 byte-exact; bracketed Host | **YES** |
| `test_native_tpc_ipv6_dual_stack_v4_to_v6` | dual-stack | `root://127.0.0.1`→`root://[::1]` byte-exact | — |
| `test_native_tpc_ipv6_dual_stack_v6_to_v4` | dual-stack | `root://[::1]`→`root://127.0.0.1` byte-exact | — |
| `test_native_tpc_ipv6_ssrf_local_denied_loopback` | security-neg | `[::1]` source, allow_local=off → pull fails pre-open; no/partial file | — |
| `test_native_tpc_ipv6_ssrf_local_allowed_loopback` | security-neg | `[::1]` source, allow_local=on → succeeds byte-exact | — |
| `test_native_tpc_ipv6_ssrf_ipv4_mapped_loopback_denied` | security-neg | `[::ffff:127.0.0.1]`, allow_local=off → rejected (v4-mapped = local) | — |
| `test_native_tpc_ipv6_ipv4_mapped_loopback_allowed` | security-neg | `[::ffff:127.0.0.1]`, allow_local=on → succeeds byte-exact | — |
| `test_native_tpc_ipv6_parse_bracket_strip_launch_rebracket` | wire-bracketing | parse bare `::1` → rebuild `root://[::1]:port`, never `root://::1:port` | **YES** |
| `test_native_tpc_ipv6_large_file_transfer` | success | >100MB v6 TPC; md5/xxhash byte-for-byte; no truncation | — |
| `test_webdav_tpc_ipv6_host_header_format` | wire-bracketing | outbound curl `Host: [::1]:port`, not bare (`proxy_pool.c:167`) | **YES** |
| `test_webdav_tpc_ipv6_curl_resolve_bracketed` | wire-bracketing | `CURLOPT_RESOLVE` `[::1]` form (`tpc_curl.c:77`); PUT to `[::1]` ok | — |
| `test_native_tpc_ipv6_connect_getaddrinfo_af_unspec` | regression | connect to `[::1]` via AF_UNSPEC; no AF_INET-only hardcode (already correct) | — |
| `test_native_tpc_ipv6_ssrf_check_src_policy_preflight` | regression | `[::1]` SSRF-denied before dst fd alloc; log gives reason; dst empty | — |
| `test_native_tpc_ipv6_socket_timeout_respected` | regression | unresponsive `[::1]` → connect times out within `TPC_CONNECT_TIMEOUT_SEC` | — |
| `test_native_tpc_ipv6_origin_id_generation` | regression | `tpc_origin` well-formed `user.pid@host` for IPv6 peer | — |

#### 7.2.7 `tests/test_ipv6_admin_ratelimit_metrics.py` — dashboard / admin API / ACL / rate-limit / metrics over IPv6

Covers the admin-API server-URI bracket parse (`api_admin.c:368-432`/`:395`), bare-host JSON registration, drain/undrain/remove, host validation, the rate-limit IP-key format (`ratelimit_keys.c:44-99`), the **cardinality invariant #8** metric-label checks, admin CIDR ACL / bearer auth, the authdb IPv6 exact+CIDR regressions (`path/authdb.c:285-344`), dual-stack metrics, and audit/error JSON formatting. Uses `ipv6-admin` (`:21600`) + `ipv4-admin` (`:21601`).

| Test | Kind | Assertion | Gates 36 |
|---|---|---|:--:|
| `test_ipv6_loopback_available` | regression | `bind(("::1",0))` ok or `pytest.skip` | — |
| `test_ipv6_admin_instance_startup` | success | `[::1]:21600` reachable; kXR_ping → kXR_ok; data root exists | — |
| `test_admin_api_register_ipv6_host_via_uri` | wire-bracketing | POST `/cluster/servers/[2001:db8::1]/1234` → 200; brackets stripped to match registry | **YES** |
| `test_admin_api_register_ipv6_host_json_body` | success | JSON `{"host":"::1",...}` → 200; bare literal accepted | — |
| `test_admin_api_drain_ipv6_server_uri_bracket_parse` | wire-bracketing | `/[::1]/21600/drain` → 200; `xrootd_srv_blacklist("::1",...)` matches | **YES** |
| `test_admin_api_undrain_ipv6_server_uri_bracket_parse` | wire-bracketing | `/[::ffff:127.0.0.1]/21601/undrain` → 200; brackets stripped | **YES** |
| `test_admin_api_remove_ipv6_server_uri` | wire-bracketing | DELETE `/[2001:db8::42]/5555` → 200; canonical-host lookup removes entry | **YES** |
| `test_admin_api_ipv6_host_validation_rejects_malformed` | security-neg | malformed literal → 400 invalid_field | — |
| `test_ratelimit_key_ipv6_client_bare_ip` | regression | key `ip::1%Z`; rbtree lookup + token charge succeed | — |
| `test_ratelimit_key_ipv6_no_bare_address_in_metric_label` | regression | no raw IPv6 in throttle metric labels (hashed/principal only) | — |
| `test_ratelimit_ipv6_bandwidth_limit_via_http` | regression | HTTP `::1` upload charges bucket keyed by `peer_ip`; metric increments | — |
| `test_admin_api_ipv6_cidr_acl_allow` | regression | `xrootd_admin_allow ::1/128` → POST from `::1` 200 (`ngx_cidr_match`) | — |
| `test_admin_api_ipv6_cidr_acl_deny` | regression | `allow 127.0.0.1/32`, `::1` no bearer → 403 | — |
| `test_admin_api_bearer_secret_ipv6_client` | regression | correct bearer from `::1` → 200 (`CRYPTO_memcmp`) | — |
| `test_authdb_ipv6_host_acl_exact_match` | regression | `p ::1 /host r` exact-match branch → open ok | — |
| `test_authdb_ipv6_cidr_slash128_match` | regression | `p ::1/128 /hostcidr r` prefix match → open ok | — |
| `test_authdb_ipv6_cidr_slash64_deny_other` | regression | `p 2001:db8::/64` vs `2001:db8::1:1` → prefix mismatch denied | — |
| `test_authdb_ipv6_ipv4_mapped_address` | regression | `p ::ffff:127.0.0.1 /mapped r` matches mapped form | — |
| `test_metrics_ipv6_connection_labels_no_raw_address` | regression | `/metrics` connection labels carry no raw `::1` (invariant #8) | — |
| `test_metrics_ipv6_dual_stack_both_listeners` | dual-stack | `:21602` dual; both families increment `connections_total{port}`; no double-count | — |
| `test_dashboard_api_ipv6_client_request` | success | `/api/v1/snapshot` from `::1` → 200/401, valid JSON `schema=xrootd-dashboard.v1` | — |
| `test_admin_api_ipv6_audit_log_format` | regression | audit line `client=` field well-formed IPv6; no garbage | — |
| `test_admin_api_ipv6_error_response_format` | success | bad JSON from `::1` → 400; valid JSON `{"error":"invalid_json"}` | — |
| `test_admin_parse_server_uri_bracket_stripping_edge_cases` | wire-bracketing | `[::1]/1234`, `[2001:db8::...]/5555`, pre-bracketed, bare-colon all split + strip correctly | **YES** |
| `test_admin_api_ipv6_concurrent_register_drain` | success | concurrent register/drain/undrain/remove → consistent registry, no TOCTOU | — |
| `test_ratelimit_ipv6_principal_vo_fallback` | regression | `key=VO` + no VO → fallback `ip::1%Z`; still throttled | — |
| `test_admin_api_all_cluster_operations_ipv6_hosts` | success | end-to-end register→list→drain→undrain→remove with `[::1]` URIs; consistent bracket handling | **YES** |

### 7.3 Acceptance (gating) vs regression

**GATING — red until the §3 fix lands, green after** (these encode the bracket-on-emit contract; CI marks them `xfail(strict)` against the unfixed tree, flipping to `xpass`→remove-marker as each fix merges):

| Fix site (§3) | Gating tests |
|---|---|
| `response/control.c:71` — kXR_redirect host | `…stream::test_ipv6_redirect_bracket_format_gating`; `…cms::{test_ipv6_cluster_locate_returns_redirect, _locate_host_is_bracketed, _open_returns_redirect, _client_follows_redirect_and_reads, test_dual_stack_ipv4_client_to_ipv6_ds_redirect, test_ipv6_cluster_multi_server_selection, test_ipv6_three_tier_topology_redirects_bracketed, test_ipv6_manager_map_redirect_host_bracketed, test_bare_ipv6_literal_in_redirect_rejected_or_normalized}` |
| `manager/registry.c:804/256` + `cms/server_*` — locate/registry host | `…stream::test_ipv6_registry_locate_bracket_format_gating`; `…cms::test_ipv6_registry_locate_body_all_entries_bracketed` |
| `webdav/proxy_pool.c:167` + `proxy_config.c:76` — proxy `Host:` | `…webdav_xrdhttp::test_ipv6_proxy_host_header_not_bare`; `…webdav_proxy::{test_ipv6_proxy_get_small_file, _put_small_file, _get_large_file, _host_header_dual_port_default, _host_header_non_default_port, _config_parse_brackets}`; `…webdav_xrdhttp::test_ipv6_dual_stack_ipv4_client_to_ipv6_backend`; `…tpc::test_webdav_tpc_ipv6_host_header_format` |
| `tpc/launch.c:180` — native-TPC URL rebuild | `…stream::test_ipv6_tpc_url_round_trip_bracket_gating`; `…tpc::{test_native_tpc_ipv6_local_v6_to_v6, _local_v6_to_v6_first, _register_stream_transfer, _parse_bracket_strip_launch_rebracket}`; `…webdav_xrdhttp::test_ipv6_tpc_url_roundtrip_bracketed` |
| `tpc/connect.c` SSRF through re-bracket round-trip | `…stream::test_ipv6_security_neg_tpc_ssrf_loopback_blocked`; `…webdav_xrdhttp::{test_ipv6_tpc_ssrf_policy_still_blocks_localhost, _ssrf_ipv4_mapped_still_blocked}` |
| `webdav/macaroon_endpoint.c:416` — Location host | `…webdav_xrdhttp::{test_ipv6_macaroon_endpoint_location_url, _token_roundtrip}` |
| `webdav/propfind.c` href (assert never absolute/host-embedded) | `…webdav_xrdhttp::{test_ipv6_webdav_propfind_depth_0, _depth_1, _href_no_host_literal, _move_destination_header_bracketed, _copy_destination_header}` |
| `dashboard/api_admin.c:395` — admin server-URI bracket strip | `…admin::{test_admin_api_register_ipv6_host_via_uri, _drain_…, _undrain_…, _remove_ipv6_server_uri, _parse_server_uri_bracket_stripping_edge_cases, test_admin_api_all_cluster_operations_ipv6_hosts}` |
| S3 cross-stack redirect bracketing | `…s3::test_s3_dual_stack_ipv4_client_to_ipv6_redirect` |

**REGRESSION — must pass today (these guard the §5 "already correct, do not touch" surface and the non-bracketing functional paths):**

- **Local locate already brackets** (`read/locate.c:182-204`): `…stream::test_ipv6_locate_local_brackets_regression`.
- **authdb IPv6 CIDR/exact** (`path/authdb.c:285-344`): `…webdav_xrdhttp::test_ipv6_webdav_authdb_ipv6_peer`; `…admin::{test_authdb_ipv6_host_acl_exact_match, _cidr_slash128_match, _cidr_slash64_deny_other, _ipv4_mapped_address}`.
- **AF_UNSPEC outbound + per-candidate SSRF + timeout** (`tpc/connect.c:107-149`, `compat/net_target.c`): `…tpc::{test_native_tpc_ipv6_connect_getaddrinfo_af_unspec, _ssrf_check_src_policy_preflight, _socket_timeout_respected, _origin_id_generation, all four SSRF allow/deny cases}`.
- **AF_INET6 detection + metrics cardinality** (`connection/handler.c`, invariant #8): `…stream::test_ipv6_handshake_wire_ipv6_peer_addr`; `…admin::{test_ratelimit_key_ipv6_*, test_metrics_ipv6_*, _cidr_acl_*, _bearer_secret_*, _audit_log_format, _principal_vo_fallback}`.
- **`redir_cache`/tried-list with IPv6 host**: `…cms::{test_ipv6_tried_cache_redirect_loop_avoidance, _redir_cache_stores_bracketed_host, _cluster_nonexistent_returns_not_found, _cluster_stat_redirects_identically_to_open, _cms_gone_deregistration}`.

All remaining `success` / `dual-stack(v6→v4)` / `security-neg` cases that do not depend on a bracketing fix are functional checks that pass once the IPv6 instance is up (they exercise the already-clean socket/resolution layer over `[::1]`).

### 7.4 Coverage matrix

Each cell names the test file(s) covering that protocol × dimension. ✓ in **wire-bracketing** marks a dimension that contains gating acceptance tests.

| Protocol | direct-v6 | wire-bracketing | dual-stack | security-neg | regression |
|---|---|---|---|---|---|
| **root:// stream** | `test_ipv6_xrootd_stream` | `test_ipv6_xrootd_stream` ✓ | `test_ipv6_xrootd_stream` | `test_ipv6_xrootd_stream` | `test_ipv6_xrootd_stream` |
| **CMS / clustering** | `test_ipv6_cms_redirect` | `test_ipv6_cms_redirect` ✓ | `test_ipv6_cms_redirect` | — (SSRF in tpc) | `test_ipv6_cms_redirect` |
| **WebDAV / XrdHttp** | `test_ipv6_webdav_xrdhttp` | `test_ipv6_webdav_xrdhttp` ✓ | `test_ipv6_webdav_xrdhttp` | `test_ipv6_webdav_xrdhttp` | `test_ipv6_webdav_xrdhttp` |
| **WebDAV proxy / mirror** | `test_ipv6_webdav_proxy` | `test_ipv6_webdav_proxy` ✓ | `test_ipv6_webdav_proxy` | — | `test_ipv6_webdav_proxy` |
| **S3** | `test_ipv6_s3` | `test_ipv6_s3` ✓ (redirect) | `test_ipv6_s3` | `test_ipv6_s3` | `test_ipv6_s3` |
| **TPC (native + WebDAV)** | `test_ipv6_tpc` | `test_ipv6_tpc` ✓ | `test_ipv6_tpc` | `test_ipv6_tpc` | `test_ipv6_tpc` |
| **dashboard / admin / ratelimit / metrics** | `test_ipv6_admin_ratelimit_metrics` | `test_ipv6_admin_ratelimit_metrics` ✓ | `test_ipv6_admin_ratelimit_metrics` | `test_ipv6_admin_ratelimit_metrics` | `test_ipv6_admin_ratelimit_metrics` |

### 7.5 Client / harness notes

- **XRootD Python client (PyXRootD `xrdcp`/`xrdfs`)** builds `root://[::1]:<port>//path` — bracketed literals are supported and the library creates the `AF_INET6` socket automatically. Use PyXRootD or raw sockets as the primary vector; some legacy `xrdcp`/`xrdfs` binaries mishandle bracketed literals in redirect bodies — which is exactly the **client-side caveat** the gating tests are written to expose, so wire-level tests use raw frames rather than relying on the client to re-parse.
- **`requests` / `urllib3` / `curl`** handle IPv6 URLs natively: `https://[::1]:<port>/` (RFC 3986 bracket syntax). For TPC `CURLOPT_RESOLVE` the entry is `[::1]:<port>:<ip>` (curl ≥ 7.21.3). Always include an explicit port in every URL — some paths normalize/unbracket when the port is omitted.
- **Raw-wire tests** reuse the existing helpers in `tests/test_handshake_protocol_wire.py` and `tests/test_pgread_wire_conformance.py` (kXR frame build + socket); for IPv6 they connect via `socket.create_connection(("::1", port))`, which yields an `AF_INET6` socket automatically. For ambiguity-free addressing prefer `socket.getaddrinfo("::1", port, socket.AF_INET6, socket.SOCK_STREAM)` and never connect to `"localhost"` (avoids `AF_UNSPEC` IPv4 fallback).
- **Skip-if-no-IPv6** is mandatory and centralized: the `requires_ipv6_loopback` fixture (§7.1.2) probes `socket.socket(AF_INET6).bind(("::1", 0))` once per session; each fixture then calls `reachable6(<PORT>)` and `pytest.skip`s if the dedicated instance is down. This composes with the existing `_reachable()`/`pytest.skip` discipline of `test_open_flags_lifecycle.py::wr_stack` and `test_vo_acl.py::vo_nginx` — no IPv6-absent or instance-down condition ever fails the suite.
- **Pre-started integration**: all IPv6 instances are launched in `start_all_dedicated()` (`manage_test_servers.sh`) alongside the existing dedicated servers, using the same `start_dedicated_nginx "<name>" "nginx_<name>.conf" "<port>"` call and `substitute_config` placeholder fill, with the one addition of `{BIND6_HOST}=[::1]` (§7.1.1). `tests/manage_test_servers.sh start_all_dedicated` reports a bind failure if the nginx binary was built without IPv6 support, so a silent IPv6-disabled build surfaces at startup rather than as opaque test failures. Buffer-widening prerequisite: `context.h:141 peer_ip` and `pmark.h:118-119` must be widened to `INET6_ADDRSTRLEN + 16` **with a full rebuild** (mixed-ABI stale-object crash) before `test_ipv6_handshake_wire_ipv6_peer_addr` and the link-local cases are meaningful.

## 8. Verification

Build clean (`-Werror`); the IPv6 round-trip tests above pass against an IPv6-listening dedicated instance; a dual-stack cluster (IPv4 client → IPv6 data server redirect) transfers byte-exact; the existing IPv4 suites are unchanged (regression). Confirm metric labels carry no raw IPv6 (cardinality invariant #8).
