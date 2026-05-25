# XRootD Feature Matrix & Interoperability Reference

Cross-reference of every XRootD protocol feature, security plugin, and server
component (from `/tmp/xrootd-src`, v5.2.0) against its implementation in
nginx-xrootd. Intended for assessing interoperability and prioritising
development work.

**Companion documents**:
- [gaps-vs-xrootd.md](gaps-vs-xrootd.md) — OSS/storage plugin gaps (tape,
  CSI, PSS, Ceph, Frm, PFC, …)
- [xrdhttp-parity-roadmap.md](xrdhttp-parity-roadmap.md) — HTTP/WebDAV TPC
  and cluster-topology roadmap

**Legend**: ✅ implemented · ⚠️ partial · ❌ not implemented · N/A not applicable

---

## 1. Protocol Opcodes

XRootD v5.2.0 defines 33 active request codes (3000–3032) in
`XProtocol/XProtocol.hh`. The legacy `kXR_gpfile` (3005) was retired before
v3 and is omitted.

| Opcode | Code | nginx-xrootd source | Status | Interop test |
|--------|------|---------------------|--------|--------------|
| kXR_auth | 3000 | src/session/login.c, src/gsi/, src/token/, src/sss/ | ✅ | test_gsi_security.py, test_token_auth.py |
| kXR_query | 3001 | src/query/dispatch.c | ✅ | test_query.py, test_interop_query.py |
| kXR_chmod | 3002 | src/write/chmod.c | ✅ | test_fs_ops.py, test_interop_namespace.py |
| kXR_close | 3003 | src/read/close.c | ✅ | test_conformance.py |
| kXR_dirlist | 3004 | src/dirlist/handler.c | ✅ | test_conformance.py |
| kXR_protocol | 3006 | src/session/protocol.c | ✅ | test_protocol_edge_cases.py, test_interop_protocol.py |
| kXR_login | 3007 | src/session/login.c | ✅ | test_protocol_edge_cases.py |
| kXR_mkdir | 3008 | src/write/mkdir.c | ✅ | test_fs_ops.py, test_interop_namespace.py |
| kXR_mv | 3009 | src/write/mv.c | ✅ | test_fs_ops.py, test_interop_namespace.py |
| kXR_open | 3010 | src/read/open.c, src/write/ | ✅ | test_conformance.py, test_interop_namespace.py |
| kXR_ping | 3011 | src/session/lifecycle.c | ✅ | test_conformance.py |
| kXR_chkpoint | 3012 | src/write/chkpoint.c | ✅ | test_write.py |
| kXR_read | 3013 | src/read/read.c | ✅ | test_conformance.py |
| kXR_rm | 3014 | src/write/rm.c | ✅ | test_fs_ops.py, test_interop_namespace.py |
| kXR_rmdir | 3015 | src/write/rmdir.c | ✅ | test_fs_ops.py, test_interop_namespace.py |
| kXR_sync | 3016 | src/write/sync.c | ✅ | test_interop_io.py |
| kXR_stat | 3017 | src/read/stat.c | ✅ | test_conformance.py |
| kXR_set | 3018 | src/query/set.c | ✅ | test_query.py |
| kXR_write | 3019 | src/write/write.c | ✅ | test_conformance.py, test_write.py |
| kXR_fattr | 3020 | src/fattr/ | ✅ | test_fattr_query.py, test_interop_namespace.py |
| kXR_prepare | 3021 | src/query/prepare.c | ✅ | test_prepare_staging.py, test_interop_query.py |
| kXR_statx | 3022 | src/read/statx.c | ✅ | test_interop_namespace.py |
| kXR_endsess | 3023 | src/session/lifecycle.c | ✅ | test_interop_protocol.py |
| kXR_bind | 3024 | src/session/bind.c | ✅ | test_session_bind.py |
| kXR_readv | 3025 | src/read/readv.c | ✅ | test_readv.py, test_interop_io.py |
| kXR_pgwrite | 3026 | src/write/pgwrite.c | ✅ | test_pgwrite_checksum.py, test_interop_io.py |
| kXR_locate | 3027 | src/read/locate.c | ✅ | test_interop_io.py |
| kXR_truncate | 3028 | src/write/truncate.c | ✅ | test_interop_namespace.py |
| kXR_sigver | 3029 | src/session/signing.c | ✅ | test_sigver_verify.py |
| kXR_pgread | 3030 | src/read/pgread.c | ✅ | test_interop_io.py |
| kXR_writev | 3031 | src/write/writev.c | ✅ | test_interop_io.py |
| kXR_clone | 3032 | src/read/ | ✅ | test_new_opcodes.py, test_interop_io.py |

**Note**: kXR_gpfile (3005) is a retired opcode from XRootD v1–v2 (renamed
kXR_getfile). No current client sends it; nginx-xrootd returns `kXR_Unsupported`.

---

## 2. kXR_query Subtypes

`XProtocol.hh` defines 13 named query codes. Source:
`XrdXrootd/XrdXrootdXeq.cc`.

| Subtype | Code | XRootD source | nginx-xrootd | Notes |
|---------|------|---------------|--------------|-------|
| kXR_QStats | 1 | XrdXrootdStats.cc | ✅ src/query/metadata.c | Format differs: nginx returns abbreviated counters; XRootD returns XML monitoring blob |
| kXR_QPrep | 2 | XrdXrootdPrepare.cc | ✅ src/query/prepare.c | Disk-local staging status; returns `A <path>` or `M <path>` per requested file |
| kXR_Qcksum | 3 | XrdXrootdXeq.cc | ✅ src/query/checksum_qcksum.c | adler32, crc32, crc32c, md5, sha1, sha256 supported |
| kXR_Qxattr | 4 | XrdXrootdXeqFAttr.cc | ✅ src/query/metadata.c | Returns standard metadata (oss.*) plus user extended attributes (U.*) |
| kXR_Qspace | 5 | XrdOssSpace.cc | ✅ src/query/space.c | statvfs-based; same `oss.space` format |
| kXR_Qckscan | 6 | XrdXrootdXeq.cc | ✅ src/query/checksum_ckscan_dispatch.c | Batch checksum scan of a directory tree; adler32 default, crc32c prefix supported |
| kXR_Qconfig | 7 | XrdXrootdConfig.cc | ✅ src/query/config.c | Key-value queries; supports tpc, chksum, readv, etc. |
| kXR_Qvisa | 8 | XrdXrootdXeq.cc | ✅ src/query/metadata.c | Returns auth identity; format matches convention |
| kXR_QFinfo | 9 | XrdXrootdXeq.cc | ✅ src/query/metadata.c | Returns file metadata (size, type) |
| kXR_QFSinfo | 10 | XrdXrootdXeq.cc | ✅ src/query/space.c | Standard 6-number space report format (NodesRW FreeMB Util NodesStaging FreeMB Util) |
| kXR_Qopaque | 16 | plugin hook | ✅ (pass-through) | Returns unsupported in non-plugin mode |
| kXR_Qopaquf | 32 | plugin hook | ✅ (pass-through) | File-scoped opaque query |
| kXR_Qopaqug | 64 | plugin hook | ✅ (pass-through) | Group-scoped opaque query |

---

## 3. Authentication Plugins (XrdSec\*)

XRootD ships six authentication protocol plugins plus macaroon and SciToken
integrations. Source: `src/XrdSec*/`, `src/XrdMacaroons/`, `src/XrdSciTokens/`.

| XRootD plugin | Protocol tag | nginx-xrootd equivalent | Status | Notes |
|---------------|--------------|------------------------|--------|-------|
| XrdSecgsi | `gsi` | src/gsi/ | ✅ | X.509 proxy + CRL; full VOMS attribute extraction via src/voms/ |
| XrdSecsss | `sss` | src/sss/ | ✅ | Keytab-based shared secret |
| XrdSecunix | `unix` | — | ❌ | UID/GID from OS credentials; no equivalent planned |
| XrdSecpwd | `pwd` | — | ❌ | Password authentication; no equivalent planned |
| XrdSeckrb5 | `krb5` | — | ❌ | Kerberos 5 GSSAPI; no equivalent planned |
| XrdSecztn | `ztn` | src/token/validate.c | ✅ | WLCG/JWT bearer token authentication |
| XrdMacaroons | bearer token | src/token/macaroon.c | ⚠️ | HMAC-SHA256 validation and caveat checking implemented; third-party delegation not implemented |
| XrdSciTokens | scitokens | src/token/validate.c | ✅ | JWT/WLCG bearer token validation and path-scope authorization implemented |
| XrdVoms | (gsi extension) | src/voms/ | ✅ | Runtime dlopen of libvomsapi; VO ACL via xrootd_require_vo |

**High-priority gap**: `krb5` is required at CERN, BNL, and Fermilab Kerberos
sites. Adding inbound krb5 support would unblock those deployments without
changing any downstream client configuration.

---

## 4. Security & TLS Capabilities

XRootD v5 introduced structured TLS capability flags in the `kXR_protocol`
handshake. Source: `XrdXrootd/XrdXrootdProtocol.cc`, `XrdTls/`.

| Feature | XRootD constant | nginx-xrootd | Notes |
|---------|-----------------|--------------|-------|
| In-protocol TLS upgrade | kXR_ableTLS / kXR_gotoTLS | ✅ src/connection/tls.c | Server advertises kXR_haveTLS; client requests upgrade via kXR_ableTLS |
| TLS at login | kXR_tlsLogin | ✅ | Enforced when xrootd_tls on |
| TLS for data channel | kXR_tlsData | ⚠️ | Negotiated but not independently enforced post-login |
| TLS for full session | kXR_tlsSess | ⚠️ | Follows login TLS; no separate directive |
| TLS for TPC | kXR_tlsTPC | ✅ | TPC over TLS works; kXR_tlsTPC capability flag advertised |
| GPF TLS | kXR_tlsGPF / kXR_tlsGPFA | ❌ | Batch file operations over TLS; not implemented |
| Request signing | kXR_sigver | ✅ src/session/signing.c | HMAC-SHA256 envelope; enforced when GSI security policy requires it |
| Security level: none | kXR_secNone | ✅ | Default |
| Security level: compatible | kXR_secCompatible | ✅ src/handshake/sigver.c | Mirrors XRootD request-protection table; conditional `open`/`set` handling |
| Security level: standard | kXR_secStandard | ✅ src/handshake/sigver.c | Enforces signed `open` and signed mutating namespace/metadata ops |
| Security level: intense | kXR_secIntense | ✅ src/handshake/sigver.c | Expands signed operation set using XRootD defaults |
| Security level: pedantic | kXR_secPedantic | ✅ src/handshake/sigver.c | Advertises `kXR_secOData`; rejects `kXR_nodata` on payload-bearing signed requests |

---

## 5. Server Capability Flags

Flags advertised in the `kXR_protocol` response body. Source:
`XProtocol/XProtocol.hh` (kXR_is* / kXR_attr* family).

| Flag | Meaning | nginx-xrootd | Condition |
|------|---------|--------------|-----------|
| kXR_isServer | Data-serving node | ✅ | Default mode |
| kXR_isManager | Redirector node | ✅ | xrootd_manager_mode on |
| kXR_attrProxy | Proxy mode | ⚠️ | xrootd_proxy on; flag not always set |
| kXR_attrCache | Cache-capable | ⚠️ | xrootd_cache on; flag not always set |
| kXR_attrMeta | Metadata-only | ❌ | Not applicable |
| kXR_attrVirtRdr | Virtual redirector | ❌ | Not implemented |
| kXR_attrSuper | Supervisor role | ❌ | Not implemented |
| kXR_suppgrw | pgread/pgwrite supported | ✅ | Always advertised |
| kXR_supposc | POSC (persist-on-close) | ✅ | Always advertised |
| kXR_haveTLS | TLS available | ✅ | xrootd_tls on |
| kXR_recoverWrts | Write recovery | ❌ | Not implemented |
| kXR_collapseRedir | Collapse redirects | ❌ | Not implemented |
| kXR_ecRedir | Erasure-code redirect | ❌ | Not implemented |
| kXR_anongpf | Anonymous GPF | ❌ | Not implemented |
| kXR_supgpf | GPF (grouped parallel fetch) | ❌ | Not implemented |

---

## 6. Client Capability Flags (kXR_login request)

Flags that clients send in the `kXR_login` request body that the server must
handle or ignore gracefully.

| Flag | Meaning | nginx-xrootd | Notes |
|------|---------|--------------|-------|
| kXR_fullurl | Client wants full URL in responses | ✅ | Full redirect URLs returned |
| kXR_multipr | Client supports multiple protocols | ❌ | Ignored; single-protocol responses only |
| kXR_readrdok | Client accepts read redirects | ✅ | Used for locate/redirect responses |
| kXR_hasipv64 | Client has IPv4+IPv6 dual-stack | ⚠️ | Accepted; IPv6 handling depends on nginx bind config |
| kXR_onlyprv4 | Client is IPv4-only | ⚠️ | Accepted; nginx filters addresses at OS level |
| kXR_onlyprv6 | Client is IPv6-only | ⚠️ | Accepted |
| kXR_lclfile | Client wants local-file fast path | ❌ | Ignored |
| kXR_redirflags | Client understands redirect flags | ✅ | Used in kXR_redirect responses |
| kXR_ecredir | Client understands EC redirects | ❌ | Ignored |

---

## 7. Checksum Support

XRootD implements checksums at two layers: (a) file-level via `kXR_Qcksum` /
`kXR_dirlist` dstat, and (b) page-level via pgread/pgwrite wire protocol.
Source: `src/XrdCks/`.

| Algorithm | File-level (kXR_Qcksum) | pgread/pgwrite wire | kXR_dirlist dstat | HTTP Digest (GET) | XRootD default |
|-----------|------------------------|---------------------|-------------------|-------------------|----------------|
| adler32 | ✅ | N/A | ✅ xattr-cached | ✅ `?xrd.want.cksum=adler32` | Yes (recommended) |
| crc32c | ✅ | ✅ wire-only | ✅ xattr-cached | ✅ `?xrd.want.cksum=crc32c` | No |
| crc32 | ✅ | N/A | ✅ xattr-cached | ✅ `?xrd.want.cksum=crc32` | No |
| md5 | ✅ | N/A | ✅ xattr-cached | ✅ `?xrd.want.cksum=md5` | Optional |
| sha256 | ✅ | N/A | ✅ xattr-cached | ✅ `?xrd.want.cksum=sha256` | No |
| sha1 | ✅ | N/A | ✅ xattr-cached | ✅ `?xrd.want.cksum=sha1` | No |

**dstat xattr cache:** All algorithms store computed checksums in `user.XrdCks.<algo>` extended attributes (via `fsetxattr`).
Subsequent listings for the same file pay only an O(1) `fgetxattr` syscall instead of re-reading the file.
Requires the filesystem to be mounted with `user_xattr` support (ext4, XFS, tmpfs all support this by default).
The cache is not mtime-invalidated — callers writing new data should evict the xattr on close (future work).

---

## 8. CMS / Cluster Features

XRootD's Cluster Management System (XrdCms) provides hierarchical server
discovery, health checking, file location, and load balancing. Source:
`src/XrdCms/`.

| Feature | XrdCms component | nginx-xrootd | Notes |
|---------|-----------------|--------------|-------|
| Server→manager heartbeat | XrdCmsClient | ✅ src/cms/send.c | Periodic heartbeat + free-space reporting |
| Manager registration | XrdCmsLogin | ✅ src/cms/ | Registers paths on startup |
| Static prefix routing | (config) | ✅ xrootd_manager_map | Longest-prefix match |
| Dynamic server registry | XrdCmsCluster | ✅ src/manager/registry.c | Hash-table with configurable slots |
| kXR_locate file lookup | XrdCmsFinder | ✅ src/read/locate.c | Returns host:port list |
| kXR_redirect | XrdCmsResp | ✅ | 302-style redirect in open/locate |
| Two-tier hierarchy (data + manager) | XrdCmsManager | ✅ | Manager + N data servers |
| Multi-tier hierarchy (manager + sub-manager) | XrdCmsSupervisor | ⚠️ | Two tiers supported; deeper hierarchies untested |
| Server blacklisting | XrdCmsBlackList | ❌ | Not implemented |
| Per-server performance metrics | XrdCmsPerfMon | ❌ | No load-aware routing |
| Virtual node ID | XrdCmsVnId | ❌ | Not implemented |
| CMS admin interface | XrdCmsAdmin | ❌ | No admin socket |
| Colocation hint (kXR_coloc in prepare) | XrdCmsPrepare | ⚠️ | Flag accepted; not acted on |
| kYR_select (CMS internal locate) | XrdCmsProtocol | ⚠️ | Handled as part of CMS wire format |
| kXR_kYR_redirect | XrdCmsResp | ✅ | Redirect with tried-host list |
| Lateral 307 redirect | XrdCmsClient | ⚠️ | One level only |

---

## 9. HTTP Layer

XRootD's HTTP support lives in `src/XrdHttp/` (XRootD-over-HTTP) and
`src/XrdHttpTpc/` (HTTP third-party copy). nginx-xrootd provides a
separate WebDAV/S3 gateway.

| Feature | XrdHttp / XrdHttpTpc | nginx-xrootd | Status |
|---------|----------------------|--------------|--------|
| HTTP GET / HEAD | ✅ | ✅ src/webdav/ | ✅ |
| HTTP PUT | ✅ | ✅ src/webdav/put.c | ✅ |
| HTTP DELETE | ✅ | ✅ src/webdav/ | ✅ |
| WebDAV PROPFIND | ✅ | ✅ src/webdav/ | ✅ |
| WebDAV MKCOL | ✅ | ✅ src/webdav/ | ✅ |
| WebDAV MOVE / COPY | ✅ | ✅ src/webdav/ | ✅ |
| WebDAV LOCK / UNLOCK | ✅ | ✅ src/webdav/lock.c | ✅ |
| CORS support | XrdHttpCors | ✅ src/webdav/cors.c | ✅ |
| HTTP Range requests | ✅ | ✅ | ✅ |
| HTTP TPC pull (COPY with Credential) | XrdHttpTpc | ✅ src/webdav/tpc.c | ✅ |
| HTTP TPC perf markers (202 streaming) | XrdHttpTpc PMarkManager | ✅ | ✅ |
| HTTP TPC multi-stream | XrdHttpTpc | ❌ | Missing |
| S3 REST GET / PUT / DELETE / HEAD | — | ✅ src/s3/ | ✅ |
| S3 multipart upload | — | ✅ src/s3/multipart.c | ✅ |
| S3 presigned URLs (X-Amz-Signature) | — | ✅ src/s3/auth_sigv4_*.c | Query-string SigV4 with expiry enforcement |
| S3 STS session token compatibility | — | ✅ src/s3/auth_sigv4_verify.c | Static-secret compatibility via `xrootd_s3_allow_unsigned_session_token`; no dynamic STS credential store |
| XRootD-over-HTTP (XrdHttp protocol) | XrdHttp | ❌ | Not implemented; WebDAV/S3 serve HTTP clients |
| HTTP checksum headers (Digest:) | XrdHttpChecksum | ✅ | `?xrd.want.cksum=adler32|crc32|crc32c|md5|sha1|sha256`; emitted on GET |
| X-Xrootd-* metadata headers | XrdHttp | ✅ | Status, Requuid, Wait, Retry emitted; Proto version parsed |

---

## 10. Monitoring & Observability

nginx-xrootd exports Prometheus metrics. The `xrd.monitor` UDP protocol from
the official xrootd daemon is **deliberately not implemented and will never be
added**. It is a fire-and-forget UDP binary stream with no reliability
guarantees, a fragile undocumented wire format, and no standard consumer
ecosystem outside the legacy XRootD collector toolchain. Sites requiring WLCG
MonIT or Rucio accounting must scrape the Prometheus endpoint and adapt as
needed; that is a solved problem. The UDP protocol is not.

| Monitoring feature | XRootD (xrd.monitor) | nginx-xrootd | Notes |
|--------------------|----------------------|--------------|-------|
| Per-opcode counters | XROOTD_MON_ALL | ✅ Prometheus | |
| Per-file I/O events | XROOTD_MON_FILE | N/A | Part of UDP protocol — out of scope |
| Per-user activity | XROOTD_MON_USER | N/A | Part of UDP protocol — out of scope |
| Auth event recording | XROOTD_MON_AUTH | N/A | Part of UDP protocol — out of scope |
| Redirect events | XROOTD_MON_REDR | N/A | Part of UDP protocol — out of scope |
| Vector I/O events | XROOTD_MON_IOV | N/A | Part of UDP protocol — out of scope |
| TPC events | XROOTD_MON_TPC | N/A | Part of UDP protocol — out of scope |
| TCP connection events | XROOTD_MON_TCPMO | N/A | Part of UDP protocol — out of scope |
| Cache events | XROOTD_MON_PFC | N/A | Part of UDP protocol — out of scope |
| UDP stream (`xrd.monitor dest`) | xrd.monitor | **Never** | See above |
| Access logging (text) | xrootd.trace | ✅ xrootd_access_log | nginx access log format |
| Latency histograms | — | ✅ Prometheus | nginx-specific extension |

---

## 11. Protocol Version & Wire Compatibility

| Feature | XRootD v5.2.0 | nginx-xrootd | Notes |
|---------|--------------|--------------|-------|
| Protocol handshake magic (ROOTD_PQ=2012) | ✅ | ✅ src/protocol/wire.h | Both check magic |
| Protocol version reported | kXR_PROTOCOLVERSION=0x00000520 | ✅ | Reports 5.2.0 |
| v3 client compatibility | ✅ | ✅ | Legacy clients work |
| v4 client compatibility | ✅ | ✅ | Tested |
| v5 features (pgread/pgwrite, fattr, clone) | ✅ | ✅ | Full v5 |
| Big-endian wire encoding | ✅ | ✅ | Enforced throughout |
| kXR_oksofar streaming reads | ✅ | ✅ src/read/read.c | Chunked large reads |
| kXR_status extended response (CRC32c) | ✅ | ✅ | Used in pgwrite response |
| kXR_wait / kXR_waitresp | ✅ | ✅ | Used in CMS locate |
| kXR_attn attention codes | ✅ | ⚠️ | Partially handled (async notify not implemented) |

---

## 12. Conformance Test Coverage Map

| Operation category | Existing unit tests | nginx vs ref-XRootD conformance | Gap |
|--------------------|--------------------|---------------------------------|-----|
| Read (open/read/close) | test_file_api.py | test_conformance.py | None |
| Vector read (readv) | test_readv.py | — | **test_interop_io.py** |
| Pgread / pgwrite | test_pgwrite_checksum.py | — | **test_interop_io.py** |
| Stat (path + handle) | test_file_api.py | test_conformance.py | None |
| Statx (multi-path) | — | — | **test_interop_namespace.py** |
| Write + round-trip | test_write.py | test_conformance.py | None |
| Vector write (writev) | test_write.py | — | **test_interop_io.py** |
| Sync | — | — | **test_interop_io.py** |
| Truncate (path + handle) | test_write.py | — | **test_interop_namespace.py** |
| Mkdir / rmdir | test_fs_ops.py | — | **test_interop_namespace.py** |
| Rm | test_fs_ops.py | — | **test_interop_namespace.py** |
| Mv | test_fs_ops.py | — | **test_interop_namespace.py** |
| Chmod | test_fs_ops.py | — | **test_interop_namespace.py** |
| Fattr (xattr) | test_fattr_query.py | — | **test_interop_namespace.py** |
| Locate | test_interop_io.py | — | None |
| Clone | test_new_opcodes.py | — | **test_interop_io.py** |
| Checkpoint | test_write.py | — | — |
| Prepare | test_prepare_staging.py | — | **test_interop_query.py** |
| Query: QPrep | test_prepare_staging.py | — | None |
| Query: Qcksum | test_conformance.py | test_conformance.py | None |
| Query: Qspace | test_query.py | — | **test_interop_query.py** |
| Query: Qstats | test_query.py | — | **test_interop_query.py** |
| Query: Qconfig | test_query.py | — | **test_interop_query.py** |
| Query: Qvisa | test_query.py | — | **test_interop_query.py** |
| Query: Qckscan | test_query_extended.py | — | None |
| Protocol negotiation | test_protocol_edge_cases.py | — | **test_interop_protocol.py** |
| Error code families | test_protocol_edge_cases.py | — | **test_interop_protocol.py** |
| Endsess | — | — | **test_interop_protocol.py** |
| Open flags (retstat, new, mkpath) | test_file_api.py | — | **test_interop_protocol.py** |
| Dirlist with dstat | test_conformance.py | test_conformance.py | None |
| GSI authentication | test_gsi_security.py, test_gsi_bridge.py | — | — |
| Token authentication | test_token_auth.py | — | — |
| TLS upgrade | test_gsi_tls.py | — | — |

---

## 13. Priority Assessment

Ranked by impact on production deployments and required development effort,
drawing on the above gaps.

### Tier 1 — Blocks real deployments

No open Tier 1 XRootD protocol gaps remain in this matrix. Security level
enforcement is implemented in `src/handshake/sigver.c`.

### Tier 2 — Significant interoperability improvement

| Gap | Effort | Impact | Who needs it |
|-----|--------|--------|--------------|
| **krb5 inbound auth** | High | High | CERN, BNL, Fermilab Kerberos sites |
| **kXR_attn async notification** | Medium | Medium | Clients relying on server-push notifications |
| **HTTP multi-stream TPC** | High | Medium | FTS high-throughput transfers |

### Tier 3 — Nice to have / niche use cases

| Gap | Effort | Notes |
|-----|--------|-------|
| Multi-tier CMS hierarchy | Medium | Two-tier covers most deployments |
| kXR_coloc in prepare | Low | Hint only; ignored by most servers |
| kXR_multipr login flag | Low | Single-protocol responses are sufficient |

### Out of scope — will never be implemented

| Feature | Reason |
|---------|--------|
| **xrd.monitor UDP stream** | Fire-and-forget UDP with no reliability, undocumented binary wire format, and no standard consumer ecosystem. Defective by design. Use Prometheus. |

Features marked out of scope in [gaps-vs-xrootd.md](gaps-vs-xrootd.md)
also remain out of scope here: tape/archive backends, Ceph, HDFS, PSS, XrdFrm,
XrdBwm, XrdPfc advanced policies.

---

## References

- `XProtocol/XProtocol.hh` — Opcode and flag definitions (v5.2.0)
- `src/XrdXrootd/XrdXrootdXeq.cc` — Official server opcode dispatch
- `src/XrdSec*/` — Security protocol plugin implementations
- `src/XrdCms/` — Cluster management system
- `src/XrdCks/` — Checksum framework
- [gaps-vs-xrootd.md](gaps-vs-xrootd.md) — OSS/storage layer gaps
- [xrdhttp-parity-roadmap.md](xrdhttp-parity-roadmap.md) — HTTP/TPC roadmap
- [operation-status.md](../05-operations/operation-status.md) — Implemented feature summary
