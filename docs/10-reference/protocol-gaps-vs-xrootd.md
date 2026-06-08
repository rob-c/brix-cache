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
| `kXR_prepare` (3021) | ✅ | Path validation + configurable `xrootd_prepare_command` staging hook; no native tape protocol (ARC/Castor API) |
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
| `kXR_QPrep` | 2 | ✅ | `A`/`M` path status |
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
| `XrdSecpwd` | `pwd` | ❌ | Password auth; no equivalent planned |
| `XrdSeckrb5` | `krb5` | ✅ | Kerberos AP-REQ verification via `krb5_rd_req`, configured with `xrootd_krb5_principal` and optional `xrootd_krb5_keytab` |
| `XrdSecztn` | `ztn` | ✅ | WLCG/JWT bearer token |
| `XrdMacaroons` | bearer | ⚠️ | HMAC-SHA256 validation + caveats; third-party delegation not implemented |
| `XrdSciTokens` | scitokens | ✅ | JWT/WLCG bearer + scope enforcement |
| `XrdVoms` | gsi ext | ✅ | Runtime dlopen of libvomsapi |

**Completed high-priority gap**: inbound `krb5` support is implemented for Kerberos sites. The nginx addon detects Kerberos 5 at configure time and compiles the plugin when `pkg-config krb5` is available; configuring `xrootd_auth krb5` without compiled Kerberos support fails at nginx config validation.

**Remaining upstream plugin gap**: `XrdSecpwd` remains unimplemented. The upstream plugin is an encrypted password-file ecosystem with admin password files, server public keys, and crypto-module negotiation; a plaintext or system-password replacement would not be protocol-compatible and would be a security regression.

**Medium-priority gap**: `XrdMacaroons` third-party delegation. Full macaroon-based authorization with caveats and delegation is not implemented.

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
| `kXR_recoverWrts` | Write recovery | ❌ | Requires kXR_attn write journal; intentionally not advertised |
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
| Server blacklisting | ❌ | |
| Per-server performance metrics | ❌ | No load-aware routing |
| Virtual node ID | ❌ | |
| CMS admin interface | ❌ | No admin socket |
| Colocation hint | ⚠️ | Flag accepted, not acted on |
| Lateral 307 redirect | ⚠️ | One level only |

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

**Note**: dstat xattr cache stores checksums in `user.XrdCks.<algo>` xattrs but is not mtime-invalidated — callers writing new data should evict xattr on close (future work).

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
| `XrdPss` | Parallel storage | ❌ Out of scope |
| `XrdFss` | File system | `src/fs/` (POSIX) |

### Not implemented (out of scope — remote storage)

| Module | Description | Reason |
|--------|-------------|--------|
| `XrdOssArc` | Tape/archive integration | POSIX-backed only |
| `XrdOssCsi` | Erasure coding | No storage layer |
| `XrdOssStats` | OSS statistics | Prometheus covers monitoring |
| `XrdOssSpace` | Space management | Basic `statvfs` implemented |
| `XrdOssTrace` | Tracing | Debug via nginx logs |
| `XrdOssReloc` | File relocation | `kXR_mv` for same-filesystem |
| `XrdOssAt` | Archive transfer | POSIX-backed only |
| `XrdOssMSS` | Mass storage | POSIX-backed only |
| `XrdOssMio` | Memory-backed I/O | TLS memory buffers suffice |
| `XrdCeph` | Ceph storage | POSIX-backed only |
| `XrdFrm` | Distributed replication | Out of scope |
| `XrdPfc` | Policy file cache | Basic cache eviction works |
| `XrdBwm` | Bandwidth management | Nice-to-have |
| `XrdThrottle` | Rate limiting | Nice-to-have |
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
| HTTP TPC multi-stream | XrdHttpTpc PMarkManager | ✅ | ❌ | **Not implemented** |
| S3 REST | — | ✅ | ✅ |
| S3 multipart | — | ✅ | ✅ |
| S3 presigned URLs | — | ✅ | ✅ |
| S3 STS session tokens | — | ✅ | ✅ |
| XRootD-over-HTTP | XrdHttp | ❌ | **Not implemented** |
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
| `kXR_attn` attention codes | ⚠️ | Proxy mode relays upstream `kXR_attn` frames transparently; server never generates them natively (no write journal, no async event queue) |

---

## 13. Priority Assessment

### Tier 1 — Blocks real deployments

| Gap | Effort | Impact | Who needs it |
|-----|--------|--------|-------------|
| HTTP-TPC multi-stream | High | Medium | FTS high-throughput transfers |
| Native `kXR_attn` generation | Medium | Medium | Clients using server-push; `kXR_recoverWrts` depends on this |

### Tier 2 — Significant interoperability improvement

| Gap | Effort | Impact |
|-----|--------|--------|
| Macaroons third-party delegation | Medium | Medium |
| XrdHttp (XRootD-over-HTTP) | High | Medium |
| Server blacklisting | Medium | Medium |

### Tier 3 — Nice to have

| Gap | Effort | Notes |
|-----|--------|-------|
| `kXR_coloc` in prepare | Low | Hint only |
| `kXR_multipr` login flag | Low | Single-protocol sufficient |

### Recently completed (removed from gap list)

| Feature | Notes |
|---------|-------|
| `kXR_prepare` tape dispatch | Configurable `xrootd_prepare_command` staging hook covers all practical backends |
| Multi-tier CMS hierarchy | Three-tier (meta → sub-manager → leaf DS) implemented and tested |
| `kXR_attrMeta` / `kXR_attrSuper` / `kXR_attrVirtRdr` | All three role flags advertised via `xrootd_metadata_only`, `xrootd_supervisor`, `xrootd_virtual_redirector` |
| `kXR_collapseRedir` | SHM redirect-target cache implemented; advertised via `xrootd_collapse_redir on` |

### Out of scope

| Feature | Reason |
|---------|--------|
| `xrd.monitor` UDP stream | Fire-and-forget, fragile, no standard consumer |
| Tape/archive backends (ARC, PSS, Ceph, HDFS) | POSIX-backed only |
| Distributed replication (Frm) | Out of scope |
| Bandwidth management (BWM) | Nice-to-have |
| Rate limiting (Throttle) | Nice-to-have |
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
| **HTTP-TPC multi-stream** | High | PMarkManager state machine, multi-stream coordination |
| **Native `kXR_attn` generation** | Medium | Server-push notification channel, async event queue; also unblocks `kXR_recoverWrts` |
| **Macaroons delegation** | Medium | Macaroon library, caveat parsing, third-party token issuance |
| **XrdHttp protocol** | High | HTTP envelope encoding, opcode dispatch over HTTP |
| **Server blacklisting** | Medium | Blacklist data structure, CMS integration |
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
