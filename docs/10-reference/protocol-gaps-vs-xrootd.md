# XRootD Protocol Gap Analysis — nginx-xrootd vs upstream xrootd

> **Scope**: Comparison of nginx-xrootd (`src/`) against reference xrootd server (`/tmp/xrootd-src/src/`, v5.2.0 protocol surface). Covers all protocol opcodes, security plugins, server modules, capability flags, and optional features.
>
> **Legend**: ✅ implemented · ⚠️ partial · ❌ not implemented · N/A not applicable · 📋 out of scope

---

## 1. Protocol Opcodes (32 of 33 active opcodes implemented)

All 32 active opcodes in the protocol 5.2 table are implemented. The legacy `kXR_gpfile` (3005) is retired.

| Opcode | Status | Notes |
|--------|--------|-------|
| `kXR_auth` (3000) | ✅ | GSI, JWT, SSS, anonymous |
| `kXR_query` (3001) | ✅ | All 13 subtypes (see Section 5) |
| `kXR_chmod` (3002) | ✅ | |
| `kXR_close` (3003) | ✅ | |
| `kXR_dirlist` (3004) | ✅ | Supports `kXR_dstat`, `kXR_dcksm`, chunked responses |
| `kXR_protocol` (3006) | ✅ | TLS, signing, security levels |
| `kXR_login` (3007) | ✅ | |
| `kXR_mkdir` (3008) | ✅ | Recursive via `kXR_mkpath` |
| `kXR_mv` (3009) | ✅ | |
| `kXR_open` (3010) | ✅ | All modes, POSC, mkpath |
| `kXR_ping` (3011) | ✅ | |
| `kXR_chkpoint` (3012) | ✅ | Begin/commit/rollback/query/xeq |
| `kXR_read` (3013) | ✅ | Chunked, async, sendfile |
| `kXR_rm` (3014) | ✅ | |
| `kXR_rmdir` (3015) | ✅ | |
| `kXR_sync` (3016) | ✅ | |
| `kXR_stat` (3017) | ✅ | |
| `kXR_set` (3018) | ✅ | appid, clttl |
| `kXR_write` (3019) | ✅ | |
| `kXR_fattr` (3020) | ✅ | get/set/del/list via xattrs |
| `kXR_prepare` (3021) | ✅ | FRM-off legacy mode does path validation + optional `xrootd_prepare_command`; with `xrootd_frm on`, durable queue records and real request IDs are handled by `src/frm/`. Full upstream XrdFrm/MSS parity remains partial. |
| `kXR_statx` (3022) | ✅ | |
| `kXR_endsess` (3023) | ✅ | |
| `kXR_bind` (3024) | ✅ | Parallel streams |
| `kXR_readv` (3025) | ✅ | Up to 1024 segments |
| `kXR_pgwrite` (3026) | ✅ | Per-page CRC32c |
| `kXR_locate` (3027) | ✅ | Wildcard, redirect, local |
| `kXR_truncate` (3028) | ✅ | |
| `kXR_sigver` (3029) | ✅ | HMAC-SHA256 |
| `kXR_pgread` (3030) | ✅ | Per-page CRC32c |
| `kXR_writev` (3031) | ✅ | |
| `kXR_clone` (3032) | ✅ | Server-side range copy |
| `kXR_gpfile` (3005) | ❌ | Retired since v3 |

**Unimplemented upstream-declared codes** (not active in upstream either): `kXR_1stRequest`, `kXR_admin`, `kXR_decrypt`, `kXR_getfile`, `kXR_putfile`, `kXR_REQFENCE`, `kXR_verifyw`.

---

## 2. kXR_query Subtypes (12/13 active subtypes)

| Subtype | Code | Status | Notes |
|---------|------|--------|-------|
| `kXR_QStats` | 1 | ✅ | Abbreviated counters (format differs from upstream XML) |
| `kXR_QPrep` | 2 | ✅ | FRM-off `A`/`M` path status; FRM-on queued/staging/failed/available queue status with durable request IDs |
| `kXR_Qcksum` | 3 | ✅ | adler32, crc32, crc32c, md5, sha1, sha256 |
| `kXR_Qxattr` | 4 | ✅ | oss.* + user.* |
| `kXR_Qspace` | 5 | ✅ | statvfs-based |
| `kXR_Qckscan` | 6 | ✅ | Batch checksum scan |
| `kXR_Qconfig` | 7 | ✅ | Key-value queries |
| `kXR_Qvisa` | 8 | ✅ | Auth identity |
| `kXR_QFinfo` | 9 | ✅ | File metadata |
| `kXR_QFSinfo` | 10 | ✅ | 6-number space report |
| `kXR_Qopaque` | 16 | ✅ | Pass-through, returns unsupported |
| `kXR_Qopaquf` | 32 | ✅ | Pass-through |
| `kXR_Qopaqug` | 64 | ✅ | Pass-through |

**Gap**: `kXR_Qopaque`/`kXR_Qopaquf`/`kXR_Qopaqug` return reference-compatible unsupported responses when no FSctl plugin is present. Full plugin hooks for custom FSctl/FSinfo operations are not implemented.

---

## 3. Authentication Plugins

| Plugin | Protocol | Status | Implementation |
|--------|----------|--------|----------------|
| `XrdSecgsi` | `gsi` | ✅ | X.509 proxy + CRL + VOMS |
| `XrdSecsss` | `sss` | ✅ | Keytab-based shared secret |
| `XrdSecunix` | `unix` | ✅ | Upstream-compatible `unix\0user [group]` credentials; loopback-only by default, remote trust requires `xrootd_unix_trust_remote on` |
| `XrdSecpwd` | `pwd` | ✅ | 2-round DH-bootstrapped username+password (`src/pwd/`); opt-in `xrootd_auth pwd` + `xrootd_pwd_file`, recommended under TLS. Wire-equivalent, not the `xrdpwdadmin`/server-public-key admin ecosystem |
| `XrdSecProtocolhost` | `host` | ✅ | Reverse-DNS allowlist auth (`src/host/`); opt-in `xrootd_auth host` + `xrootd_host_allow`, identity from socket reverse-DNS only, fail-closed/trusted-network only |
| `XrdSeckrb5` | `krb5` | ✅ | Kerberos AP-REQ verification via `krb5_rd_req`, configured with `xrootd_krb5_principal` and optional `xrootd_krb5_keytab` |
| `XrdSecztn` | `ztn` | ✅ | WLCG/JWT bearer token |
| `XrdMacaroons` | bearer | ✅ | HMAC-SHA256 validation + caveats + third-party discharge bundles; `POST /.oauth2/token` issues scoped delegation macaroons; `GET /.well-known/oauth-authorization-server` discovery |
| `XrdSciTokens` | scitokens | ✅ | JWT/WLCG bearer + scope enforcement |
| `XrdVoms` | gsi ext | ✅ | Runtime dlopen of libvomsapi |

**Completed high-priority gap**: inbound `krb5` support is implemented for Kerberos sites. The nginx addon detects Kerberos 5 at configure time and compiles the plugin when `pkg-config krb5` is available; configuring `xrootd_auth krb5` without compiled Kerberos support fails at nginx config validation.

**Completed gap**: `XrdSecpwd` (`pwd`) and the built-in `host` protocol are now implemented (`src/pwd/`, `src/host/`), giving wire-equivalent coverage of every standard upstream stream auth scheme. `pwd` is implemented as the DH-bootstrapped password handshake rather than a plaintext/system-password substitute (which would be a security regression); it is the wire protocol, not the full `xrdpwdadmin` admin-file ecosystem. The only remaining auth gap is *custom* third-party sec plugins (no loadable sec-plugin ABI).

**Completed medium-priority gap**: `XrdMacaroons` third-party delegation. `POST /.oauth2/token` issues scoped WLCG macaroons from `xrootd_webdav_macaroon_secret`; HMAC chain + first-party caveats (activity, path, before) match XrdMacaroons wire format. `GET /.well-known/oauth-authorization-server` provides RFC 8414 discovery. Issued tokens are validated by the existing `xrootd_macaroon_validate_bundle()` path.

**Completed medium-priority gap**: `XrdSciTokens` path-based authorization is enforced through the shared token scope parser and identity scope checks on stream and WebDAV write paths.

---

## 4. Security & TLS Capabilities

| Feature | XRootD Constant | Status | Notes |
|---------|----------------|--------|-------|
| In-protocol TLS upgrade | `kXR_ableTLS`/`kXR_gotoTLS` | ✅ | |
| TLS at login | `kXR_tlsLogin` | ✅ | |
| TLS for data channel | `kXR_tlsData` | ⚠️ | Negotiated but not independently enforced |
| TLS for full session | `kXR_tlsSess` | ⚠️ | Follows login TLS |
| TLS for TPC | `kXR_tlsTPC` | ✅ | |
| GPF TLS | `kXR_tlsGPF`/`kXR_tlsGPFA` | ❌ | Grouped parallel fetch over TLS |
| Request signing | `kXR_sigver` | ✅ | HMAC-SHA256 envelope |
| Security levels | none/compatible/standard/intense/pedantic | ✅ | All five implemented |

---

## 5. Server Capability Flags

| Flag | Meaning | Status |
|------|---------|--------|
| `kXR_isServer` | Data-serving node | ✅ |
| `kXR_isManager` | Redirector node | ✅ |
| `kXR_attrProxy` | Proxy mode | ⚠️ |
| `kXR_attrCache` | Cache-capable | ⚠️ |
| `kXR_attrMeta` | Metadata-only (`xrootd_metadata_only on`) | ✅ |
| `kXR_attrVirtRdr` | Virtual redirector (`xrootd_virtual_redirector on`) | ✅ |
| `kXR_attrSuper` | Supervisor role (`xrootd_supervisor on`) | ✅ |
| `kXR_suppgrw` | pgread/pgwrite | ✅ |
| `kXR_supposc` | POSC | ✅ |
| `kXR_haveTLS` | TLS available | ✅ |
| `kXR_recoverWrts` | Write recovery | ✅ | Uses per-handle write journal for idempotent replay |
| `kXR_collapseRedir` | Collapse redirects (`xrootd_collapse_redir on`) | ✅ | SHM redirect-target cache in `src/manager/redir_cache.c` |
| `kXR_ecRedir` | Erasure-code redirect | ❌ |
| `kXR_anongpf` | Anonymous GPF | ❌ |
| `kXR_supgpf` | GPF | ❌ |

---

## 6. Client Capability Flags

| Flag | Meaning | Status |
|------|---------|--------|
| `kXR_fullurl` | Full URL in responses | ✅ |
| `kXR_multipr` | Multiple protocols | ❌ |
| `kXR_readrdok` | Read redirects | ✅ |
| `kXR_hasipv64` | IPv4+IPv6 dual-stack | ⚠️ |
| `kXR_onlyprv4` | IPv4-only | ⚠️ |
| `kXR_onlyprv6` | IPv6-only | ⚠️ |
| `kXR_lclfile` | Local-file fast path | ❌ |
| `kXR_redirflags` | Redirect flags | ✅ |
| `kXR_ecredir` | EC redirects | ❌ |

---

## 7. CMS / Cluster Features

| Feature | Status | Notes |
|---------|--------|-------|
| Server→manager heartbeat | ✅ | Periodic heartbeat + space |
| Manager registration | ✅ | Path registration on startup |
| Static prefix routing | ✅ | Longest-prefix match |
| Dynamic server registry | ✅ | 128-slot shared memory |
| `kXR_locate` file lookup | ✅ | Host:port list |
| `kXR_redirect` | ✅ | 302-style |
| Two-tier hierarchy | ✅ | Manager + data servers |
| Multi-tier hierarchy | ✅ | Three-tier tested: meta-manager → sub-manager → leaf DS; `nginx_cluster_sub_manager.conf` |
| Server blacklisting | ✅ | 30 s blacklist on CMS disconnect; `xrootd_srv_blacklist()` + `error_count` in SHM; cleared on reconnect |
| Per-server performance metrics | ✅ | `xrootd_cluster_server_free_megabytes`, `_utilization_percent`, `_last_seen_seconds`, `_blacklisted`, `_disconnect_total` Prometheus gauges in `src/metrics/cluster.c` |
| Virtual node ID | ❌ | |
| CMS admin interface | ❌ | No admin socket |
| Colocation hint | ✅ | `kXR_prefname` parsed; `kXR_locate` returns all matching servers — client selects by network locality |
| Lateral 307 redirect | ✅ | `kXR_locate` returns `kXR_ok` with full server list via `xrootd_srv_locate_all()`; no redirect chaining needed |

---

## 8. Checksum Support

| Algorithm | File-level (Qcksum) | pgread/pgwrite wire | dirlist dstat | HTTP Digest |
|-----------|---------------------|---------------------|---------------|-------------|
| adler32 | ✅ | N/A | ✅ | ✅ |
| crc32c | ✅ | ✅ | ✅ | ✅ |
| crc32 | ✅ | N/A | ✅ | ✅ |
| md5 | ✅ | N/A | ✅ | ✅ |
| sha256 | ✅ | N/A | ✅ | ✅ |
| sha1 | ✅ | N/A | ✅ | ✅ |

**Note**: checksum xattr caching is mediated through the shared integrity layer,
which validates cached values against file metadata and invalidates on write
paths where required.

---

## 9. Optional Server Modules (upstream vs nginx-xrootd)

### Implemented (with upstream equivalent)

| Module | Description | nginx-xrootd equivalent |
|--------|-------------|------------------------|
| `XrdXrootd` | Core protocol handler | Native `root://` stream module |
| `XrdHttp` | HTTP file serving | WebDAV (`davs://`) + S3 REST |
| `XrdHttpTpc` | HTTP TPC | WebDAV TPC via `COPY` + curl |
| `XrdCms` | Cluster management | `src/cms/` + `src/manager/` |
| `XrdCrypto` | Encryption framework | TLS transport (no data-at-rest) |
| `XrdCks` | Checksum framework | `kXR_query` checksums + pgread CRC |
| `XrdOuc` | Utilities | `src/compat/` |
| `XrdSys` | System | `src/types/` |
| `XrdNet` | Networking | `src/connection/` |
| `XrdOfs` | Object file system | `src/fs/` |
| `XrdOss` | Object storage | `src/fs/` (POSIX-backed) |
| `XrdPss` | Parallel storage | ❌ Full upstream PSS is out of scope |
| `XrdFss` | File system | `src/fs/` (POSIX) |

### Not implemented (out of scope — remote storage)

| Module | Description | Reason |
|--------|-------------|--------|
| `XrdOssArc` | Tape/archive integration | Partial via FRM/Tape REST gateway; not the full upstream archive backend |
| `XrdOssCsi` | Erasure coding | No storage layer |
| `XrdOssStats` | OSS statistics | Prometheus covers monitoring |
| `XrdOssSpace` | Space management | Basic `statvfs` implemented |
| `XrdOssTrace` | Tracing | Debug via nginx logs |
| `XrdOssReloc` | File relocation | `kXR_mv` for same-filesystem |
| `XrdOssAt` | Archive transfer | POSIX-backed only |
| `XrdOssMSS` | Mass storage | Partial control-plane integration only; no in-process MSS driver stack |
| `XrdOssMio` | Memory-backed I/O | TLS memory buffers suffice |
| `XrdCeph` | Ceph storage | POSIX-backed only |
| `XrdFrm` | Distributed replication / file residency | Partial FRM queue and Tape REST gateway; not full upstream XrdFrm daemon ecosystem |
| `XrdPfc` | Policy file cache | Partial: read-through, slice cache, eviction, and write-through helpers; not full upstream PFC |
| `XrdBwm` | Bandwidth management | Built-in identity-aware bandwidth limits exist; not upstream XrdBwm plugin parity |
| `XrdThrottle` | Rate limiting | Built-in request-rate/concurrency limits exist; not upstream XrdThrottle plugin parity |
| `XrdZip` | ZIP archive serving | Nice-to-have |
| `XrdDig` | Diagnostics | Nice-to-have |
| `XrdEc` | Event data catalog | Nice-to-have |
| `XrdRmc` | Replica management | Nice-to-have |
| `XrdFrc` | File replica catalog | Nice-to-have |
| `XrdSsi` | Storage server interface | Nice-to-have |
| `XrdSfs` | Spectrum Scale | Nice-to-have |
| `XrdPss` | Parallel storage | Nice-to-have |

---

## 10. HTTP Layer

| Feature | XRootD (XrdHttp) | nginx-xrootd | Status |
|---------|------------------|--------------|--------|
| HTTP GET / HEAD | ✅ | ✅ WebDAV | ✅ |
| HTTP PUT | ✅ | ✅ | ✅ |
| HTTP DELETE | ✅ | ✅ | ✅ |
| WebDAV PROPFIND | ✅ | ✅ | ✅ |
| WebDAV MKCOL | ✅ | ✅ | ✅ |
| WebDAV MOVE / COPY | ✅ | ✅ | ✅ |
| WebDAV LOCK / UNLOCK | ✅ | ✅ | ✅ |
| CORS | XrdHttpCors | ✅ | ✅ |
| HTTP Range | ✅ | ✅ | ✅ |
| HTTP TPC pull | XrdHttpTpc | ✅ | ✅ |
| HTTP TPC multi-stream | XrdHttpTpc PMarkManager | ✅ | ✅ | `X-Number-Of-Streams` negotiated; N parallel Range-GETs via `curl_multi`; 202+Perf Markers via `xrootd_webdav_tpc_marker_interval` |
| S3 REST | — | ✅ | ✅ |
| S3 multipart | — | ✅ | ✅ |
| S3 presigned URLs | — | ✅ | ✅ |
| S3 STS session tokens | — | ✅ | ✅ |
| XRootD-over-HTTP | XrdHttp | ✅ | `Want-Digest:` (RFC 3230) parsed on HEAD+GET; RFC 3230 algo names normalised (SHA-256→sha256, SHA→sha1); `Digest:` response header computed via xattr-cached xrootd_integrity_get_fd; `X-Xrootd-Proto`, `X-Xrootd-Requuid`, `X-Xrootd-Status`, multipart GET, ?xrd.stats, redirect dialect all implemented; POST returns 405 with `Allow:` |
| HTTP checksum headers | XrdHttpChecksum | ✅ | ✅ |
| X-Xrootd-* metadata | XrdHttp | ✅ | ✅ |

---

## 11. Monitoring

| Feature | XRootD | nginx-xrootd | Status |
|---------|--------|--------------|--------|
| Per-opcode counters | XROOTD_MON_ALL | ✅ Prometheus | ✅ |
| Per-file I/O | XROOTD_MON_FILE | N/A | ❌ UDP-only |
| Per-user activity | XROOTD_MON_USER | N/A | ❌ UDP-only |
| Auth events | XROOTD_MON_AUTH | N/A | ❌ UDP-only |
| Redirect events | XROOTD_MON_REDR | N/A | ❌ UDP-only |
| Vector I/O events | XROOTD_MON_IOV | N/A | ❌ UDP-only |
| TPC events | XROOTD_MON_TPC | N/A | ❌ UDP-only |
| TCP events | XROOTD_MON_TCPMO | N/A | ❌ UDP-only |
| Cache events | XROOTD_MON_PFC | N/A | ❌ UDP-only |
| UDP stream `xrd.monitor` | xrd.monitor | ❌ | Never implemented |
| Access logging | xrootd.trace | ✅ | ✅ |
| Latency histograms | — | ✅ Prometheus | ✅ |

---

## 12. Protocol Version & Wire Compatibility

| Feature | Status |
|---------|--------|
| Protocol magic (ROOTD_PQ=2012) | ✅ |
| Protocol version 5.2.0 | ✅ |
| v3/v4 client compatibility | ✅ |
| v5 features (pgread/pgwrite/fattr/clone) | ✅ |
| Big-endian wire | ✅ |
| `kXR_oksofar` streaming reads | ✅ |
| `kXR_status` extended response | ✅ |
| `kXR_wait` / `kXR_waitresp` | ✅ |
| `kXR_attn` attention codes | ✅ | Proxy mode relays upstream `kXR_attn` frames transparently; server generates native `kXR_attn` + `kXR_asyncms` (5002) frames; `xrootd_send_attn_asyncms()` / `xrootd_send_attn_asynresp()` in `src/response/async.c` — `kXR_notify` on `kXR_prepare` delivers immediate notification when files are on disk |

---

## 13. Priority Assessment

### Tier 1 — Blocks real deployments

*No open Tier-1 gaps.*

### Tier 2 — Significant interoperability improvement

*No open Tier-2 gaps.*

### Tier 3 — Nice to have

| Gap | Effort | Notes |
|-----|--------|-------|
| `kXR_coloc` in prepare | ✅ | Hint passed to `xrootd_prepare_command` via `XROOTD_PREPARE_COLOC=1` |
| `kXR_multipr` login flag | Low | Single-protocol sufficient |

### Recently completed (removed from gap list)

| Feature | Notes |
|---------|-------|
| **Native `kXR_attn` generation** | `xrootd_send_attn_asyncms()` / `xrootd_send_attn_asynresp()` in `src/response/async.c`; `kXR_notify` on `kXR_prepare` delivers immediate `kXR_asyncms` when files are on disk; `kXR_asynresp` available for deferred-response callers |
| `kXR_prepare` FRM/Tape REST support | Durable FRM queue + Tape REST gateway exists; full upstream XrdFrm/MSS parity is still partial |
| Multi-tier CMS hierarchy | Three-tier (meta → sub-manager → leaf DS) implemented and tested |
| `kXR_attrMeta` / `kXR_attrSuper` / `kXR_attrVirtRdr` | All three role flags advertised via `xrootd_metadata_only`, `xrootd_supervisor`, `xrootd_virtual_redirector` |
| `kXR_collapseRedir` | SHM redirect-target cache implemented; advertised via `xrootd_collapse_redir on` |
| **Server blacklisting** | 30 s temporary blacklist on CMS disconnect; `xrootd_srv_blacklist()` + `error_count` in SHM registry; cleared on reconnect (`src/manager/registry.c`) |
| **Per-server cluster metrics** | `xrootd_cluster_server_free_megabytes`, `_utilization_percent`, `_last_seen_seconds`, `_blacklisted`, `_disconnect_total` Prometheus gauges (`src/metrics/cluster.c`) |
| **Colocation hint** | `kXR_prefname` parsed; `kXR_locate` returns all matching servers — client selects by network locality |
| **Lateral redirect** | `kXR_locate` returns `kXR_ok` with full server list via `xrootd_srv_locate_all()`; no redirect chaining needed |
| **XrdHttp (XRootD-over-HTTP)** | `Want-Digest:` RFC 3230 header parsed in `xrdhttp_parse_request()`; algo names normalised (SHA-256→sha256, SHA→sha1); HEAD opens fd for checksum via `xrdhttp_add_checksum_header()`; POST returns 405 + `Allow:`; XrdClHttp plugin fully compatible |
| **Macaroons third-party delegation** | `POST /.oauth2/token` issues scoped macaroons (HMAC chain, activity/path/before caveats) from `xrootd_webdav_macaroon_secret`; `GET /.well-known/oauth-authorization-server` RFC 8414 discovery; no `libmacaroons` dependency — pure OpenSSL HMAC; issued tokens validated by existing `xrootd_macaroon_validate_bundle()` |

### Out of scope

| Feature | Reason |
|---------|--------|
| `xrd.monitor` UDP stream | Fire-and-forget, fragile, no standard consumer |
| Full tape/archive backend ecosystem (ARC, PSS, Ceph, HDFS, MSS drivers) | Narrower POSIX-backed module with FRM/Tape REST control-plane integration |
| Full distributed replication / XrdFrm daemon ecosystem | Partial FRM queue only |
| Upstream BWM/Throttle plugin parity | Built-in bandwidth/rate/concurrency policy exists, but not as those upstream plugins |
| ZIP archive serving | Nice-to-have |
| Erasure coding (CSI) | No storage layer |
| Audit logging | Access logging sufficient |
| Tracing/Debugging | Dev tool |
| OSS Stats | Prometheus sufficient |
| Event recording/streaming | Dev/monitoring tools |
| Archive transfer | POSIX-backed only |
| Mass storage | POSIX-backed only |
| Relocation | Nice-to-have |
| Space management | Basic statvfs sufficient |
| Memory-backed I/O | TLS buffers sufficient |
| Prepare/GPI | Path validation sufficient |
| FSctl/FSinfo plugins | Query hooks sufficient |
| Cache config | Basic eviction sufficient |
| Server-side copy | `kXR_clone` sufficient |
| Operation stats | Prometheus + access logs sufficient |

---

## 14. Implementation Effort Summary

### Remaining gaps

| Gap | Effort | Implementation Notes |
|-----|--------|---------------------|
| **HTTP-TPC multi-stream** | ✅ | `X-Number-Of-Streams` negotiated; `curl_multi` Range-GETs; 202+Perf Markers (`src/webdav/tpc_marker.c`, `tpc_curl.c`) |
| **Native `kXR_attn` generation** | ✅ | `xrootd_send_attn_asyncms()` / `xrootd_send_attn_asynresp()` in `src/response/async.c`; `kXR_notify` on `kXR_prepare` delivers immediate notification; `kXR_asynresp` ready for deferred-response callers |
| **Macaroons delegation** | ✅ | `POST /.oauth2/token` + `GET /.well-known/oauth-authorization-server`; HMAC-SHA256 issuance in `src/token/macaroon_issue.c`; REST handler in `src/webdav/macaroon_endpoint.c` |
| **XrdHttp protocol** | ✅ | `Want-Digest:` RFC 3230 on HEAD+GET; algo normalisation; `xrdhttp_add_checksum_header()` on HEAD; 405+Allow on unknown methods |
| **Throttle** | Low | Per-connection rate limiter |
| **ZIP serving** | Low | ZIP parser, archive extraction |

### Completed

| Feature | Notes |
|---------|-------|
| **`kXR_prepare` staging hook** | `xrootd_prepare_command` external script; covers tape (xrdcp, dmget, …) |
| **Multi-tier CMS** | Three-tier (meta-manager → sub-manager → leaf DS); `TestThreeTierTopology` passes |
| **`kXR_attrMeta`** | `xrootd_metadata_only on` — namespace ops only, file I/O returns kXR_Unsupported |
| **`kXR_attrSuper`** | `xrootd_supervisor on` — top-tier manager role |
| **`kXR_attrVirtRdr`** | `xrootd_virtual_redirector on` — path-map redirector without CMS |
| **`kXR_collapseRedir`** | `xrootd_collapse_redir on` — SHM redirect-target cache (`src/manager/redir_cache.c`) |
| **`kXR_attn` relay (proxy)** | Proxy mode transparently relays upstream `kXR_attn` frames |
| **`kXR_attn` native generation** | `xrootd_send_attn_asyncms()` + `xrootd_send_attn_asynresp()` in `src/response/async.c`; `kXR_notify` on `kXR_prepare` wired; `kXR_asyncms` / `kXR_asynresp` constants in `src/protocol/opcodes.h` |
| **Server blacklisting** | 30 s blacklist on CMS disconnect; `xrootd_srv_blacklist()` + `error_count` in SHM; clears on reconnect |
| **Per-server cluster metrics** | `xrootd_cluster_server_{free_megabytes,utilization_percent,last_seen_seconds,blacklisted,disconnect_total}` gauges in `src/metrics/cluster.c` |
| **Colocation hint** | `kXR_prefname` (0x0100) parsed; locate returns all matching servers for client-side locality selection |
| **Lateral redirect** | `kXR_locate` returns `kXR_ok` with full server list via `xrootd_srv_locate_all()`; no redirect chaining |
