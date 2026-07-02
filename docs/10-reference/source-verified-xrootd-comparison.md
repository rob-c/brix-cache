# Source-Verified XRootD Feature Comparison

Review date: 2026-06-14

Scope:

- This document compares this repository (`nginx-xrootd`) with the official
  XRootD source tree checked out at `/tmp/xrootd-src`.
- It is based on source inspection, not only on existing documentation claims.
- The official protocol header reviewed is
  `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`, which advertises protocol
  version `5.2.0`.
- UDP/XrdMon stream monitoring is explicitly excluded from gap analysis. The
  intended replacement surface here is HTTP-native observability:
  Prometheus, SRR, access logs, and the dashboard/admin APIs.

Status legend:

| Status | Meaning |
|---|---|
| Parity | Comparable source-backed implementation exists in both projects. |
| nginx+ | Implemented here with a capability not present, or not present as a server feature, in upstream XRootD. |
| Partial | Implemented here, but not the full upstream plugin ecosystem, configuration model, or semantic surface. |
| Missing | Upstream source has an implementation; no comparable implementation was found here. |
| Not counted | Deliberately excluded from this review scope. |
| Not replacement-scope | Upstream ships a client/tool/framework feature that does not need to live in the nginx module to replace an XRootD server. |

Rows may combine statuses with `/` when the source-backed answer is mixed, for
example "Parity / nginx+" when both projects implement the base feature but the
nginx module adds an operational extension.

## Executive Finding

The core native XRootD data-server surface is substantially closer to parity
than several older documents in this repository indicate. Both source trees
define the current active opcode set through `kXR_clone` (`3032`). This module
dispatches the practical data-plane, namespace, metadata, auth, signing, TLS,
and vector/paged I/O operations; the one defined request it does not implement
is `kXR_gpfile` (`3005`), and upstream's default handler also returns
`kXR_Unsupported` for `gpfile`.

The remaining material gaps are mostly not core wire-protocol gaps. They are
upstream plugin ecosystems and site policy compatibility areas:

- legacy auth plugins: `pwd` and `host`;
- full `XrdAcc` policy semantics beyond this module's authdb/VO/token scope
  model;
- optional storage plugins and services such as `XrdCeph`, `XrdPss`, the full
  `XrdPfc`/XCache stack, `XrdOssCsi`, `XrdZip`, and the complete `XrdFrm`
  daemon/admin/migrate/purge ecosystem;
- the checksum plugin framework beyond the built-in CRC64/CRC64NVME set;
- some advanced CMS/admin semantics and proxy-mode async edge cases;
- UDP monitoring, which is intentionally not a product goal.

At the same time, this module implements several capabilities that are not
present in upstream XRootD as server-side features, or are materially more
operator-friendly here:

- an S3-compatible REST server endpoint with SigV4, multipart, presigned URL,
  browser POST, batch delete, copy, and upload-part-copy support;
- one nginx-operated deployment model for native `root://`, WebDAV/XrdHttp,
  S3, metrics, dashboard, admin API, rate limiting, and TLS;
- cross-protocol Prometheus/SRR/dashboard observability instead of UDP
  monitoring;
- identity-aware request, bandwidth, and concurrency limiting across stream and
  HTTP surfaces;
- WebDAV features beyond upstream XrdHttp: `LOCK`, `UNLOCK`, `PROPPATCH`,
  dead properties, `SEARCH`, and protected `ACL` behavior;
- traffic mirroring/shadowing for migration validation;
- hardened HTTP-TPC implementation details such as DNS pinning/SSRF checks,
  credential delegation paths, dashboard visibility, and low-cardinality
  metrics;
- a WLCG Tape REST gateway and durable FRM-style staging queue, though not full
  upstream FRM parity.

The strongest replacement story is therefore: sites with POSIX-backed or
operator-staged storage that need modern HTTPS/S3/metrics/operability can use
this module as a practical replacement candidate. Sites that depend on the
historical XRootD plugin ecosystem, complex `XrdAcc` files, XrdMon UDP feeds,
Ceph/PSS/PFC backends, or full FRM daemon workflows still need explicit
migration work.

## Reviewer Attention: Documentation Corrections

This table records the stale claims found during the source-verification pass and
their current documentation status after the 2026-06-14 cleanup.

| Claim location | Previous stale claim or implication | Source-verified status | Doc status |
|---|---|---|---|
| `docs/05-operations/operation-status.md` | `krb5` auth was not planned; `kXR_prepare/kXR_stage` had no tape dispatch. | `krb5` exists in `src/auth/krb5`; FRM queue and Tape REST gateway support exist, while full XrdFrm/MSS parity remains partial. | Corrected. |
| `docs/10-reference/xrootd-feature-matrix.md` | UNIX/krb5/macaroons/XrdHttp/protocol flags were missing. | Source has `src/auth/unix`, `src/auth/krb5`, macaroon issue/verify paths, XrdHttp/WebDAV paths, and protocol-flag tests. | Replaced with a current source-verified matrix. |
| `docs/10-reference/gaps-vs-xrootd.md` | Rate limiting, XrdHttp, HTTP-TPC, FRM/tape, and delegation work were still missing. | Those features exist; remaining gaps are non-POSIX storage backends (EC/Ceph/OssArc/OssCsi), full XrdFrm/MSS parity, the loadable plugin ABI itself, and selected proxy/admin edges. (`host`/`pwd` auth are now implemented.) | Replaced with a current remaining-gaps document. |
| `docs/10-reference/comparison-nginx-xrootd-vs-canonical.md` | Upstream/canonical XRootD lacked WebDAV/HTTP-TPC and only had native TPC. | Upstream has `src/XrdHttpTpc/`; nginx adds different HTTP-TPC hardening and operational integration, not the first HTTP-TPC implementation. | Corrected and pointed at this source-verified comparison. |
| `docs/09-developer-guide/capability-flags-implementation-plan.md` | Several protocol flags were missing/planned. | `src/protocols/root/session/protocol.c` sets the implemented flags and `tests/test_protocol_flags.py` verifies them. | Marked historical. |
| `docs/05-operations/management.md` and `src/protocols/root/query/README.md` | `kXR_prepare` stage always returned request id `"0"` and kept per-session QPrep state only. | `"0"` is the FRM-off legacy path; FRM-on uses durable request records and real reqids in `src/frm/`. | Corrected. |
| `docs/04-protocols/http-tpc-reference.md` and `docs/10-reference/quirks.md` | WebDAV TPC delegation, markers, and multistream support were missing; native TPC outbound auth was anonymous-only. | WebDAV TPC has credential delegation, markers, TransferHeader handling, and curl_multi multistream paths; native TPC still has TLS-upgrade/multihop caveats. | Corrected. |
| `docs/refactor/phase-24-traffic-mirroring.md` | Write mirroring was out of scope/not implemented. | Source has HTTP/WebDAV write mirroring and stream data-write replay gated by `xrootd_mirror_writes`. | Corrected in the as-built status section. |
| `docs/refactor/phase-35-frm-tape-staging.md` | `src/frm/` was greenfield and source-list guidance was ambiguous. | `src/frm/` exists and is registered in the top-level `config` script. | Marked historical and clarified current build registration. |
| `docs/refactor/phase-8-openat2-confinement.md` | Runtime path confinement was genuinely incomplete; HTTP/S3 had no rootfd/beneath path. | `src/fs/path/README.md` documents runtime `openat2(RESOLVE_BENEATH)` confinement, stream rootfd, HTTP `common.rootfd`, and config-time-only `realpath`. | Marked as historical migration notes; stale HTTP/S3 row corrected. |
| `docs/refactor/phase-34-packet-marking-scitags.md` | Packet marking/SciTags was a future plan. | `src/observability/pmark/` implements Firefly UDP and IPv6 flow-label marking, including the XRootD-stubbed flow-label path. | Marked implemented/as-built. |
| `docs/refactor/phase-29-phase3-aio-pipelining-spec.md` and `docs/refactor/phase-30-hyper-optimization-throughput-latency.md` | AIO pipeline work was entirely unimplemented; build flags and CRC64/CRC32 premises were current. | Phase 32/33 landed response/read-buffer pipeline foundations and build defaults; CRC32C is hardware-accelerated; CRC64 is implemented separately. | Marked superseded/historical; visible stale table rows corrected. |
| `docs/09-developer-guide/feature-roadmap.md` | OCSP, discharge macaroons, authdb host/query/fattr coverage, CMS escalation tests, FRM prepare, and write-through cache details were stale. | Source has OCSP responder/stapling, macaroon discharge bundles, authdb host/CIDR plus broader handler gates, CMS tests, FRM/Tape REST, and cache-origin anonymous-login limitations. | Corrected with current caveats. |
| `docs/10-reference/comparison-nginx-xrootd-vs-canonical.md`, `docs/10-reference/gaps-vs-xrootd.md`, `docs/10-reference/xrootd-feature-matrix.md` | CRC64 was missing or grouped as a checksum gap. | `src/core/compat/crc64.c`, S3 CRC64NVME paths, and `docs/10-reference/crc64-checksums.md` show CRC64/CRC64NVME support. | Corrected; remaining checksum gap is plugin-framework breadth. |
| `docs/05-operations/proxy-mode-guide.md` | Proxy mode gaps around unsolicited `kXR_attn` and prepare path rewriting. | Source inspection found `kXR_waitresp` forwarding; complete upstream unsolicited-attention dispatch and per-entry prepare rewrite still need separate review. | Open reviewer attention item. |

## Native XRootD Protocol Surface

Source anchors:

- Upstream opcodes and protocol flags:
  `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`
- Upstream data-server dispatch:
  `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdProtocol.cc`
- Upstream `gpfile` behavior:
  `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeq.cc`
- nginx opcode definitions:
  `src/protocols/root/protocol/opcodes.h`
- nginx dispatch:
  `src/protocols/root/handshake/dispatch.c`, `src/protocols/root/handshake/dispatch_session.c`,
  `src/protocols/root/handshake/dispatch_read.c`, `src/protocols/root/handshake/dispatch_write.c`,
  `src/protocols/root/handshake/dispatch_signing.c`

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| Protocol version constants | `XProtocol.hh` advertises `kXR_PROTOCOLVERSION 0x00000520` and `5.2.0`. | `src/protocols/root/protocol/opcodes.h` advertises `0x00000520`. | Parity | The module intentionally speaks the current 5.2 wire vocabulary even if the surrounding XRootD software release number is newer. |
| Request opcodes `3000..3032` | `XProtocol.hh` defines auth through clone, including historical gaps. | `src/protocols/root/protocol/opcodes.h` defines the same visible request IDs. | Parity | `kXR_gpfile` is the only defined request without a practical handler here. |
| Handshake, protocol, login, auth | `XrdXrootdProtocol.cc`, XrdSec plugin manager. | `src/protocols/root/connection/handler.c`, `src/protocols/root/session/protocol.c`, `src/protocols/root/session/login.c`, `src/auth/gsi/auth.c`, `src/auth/token/validate.c`, `src/auth/sss/`, `src/auth/unix/`, `src/auth/krb5/`. | Parity | Auth plugin breadth differs; see auth table. |
| In-protocol TLS (`kXR_ableTLS`, `kXR_gotoTLS`, `kXR_tlsLogin`) | XrdTls/XrdXrootd protocol path. | `src/protocols/root/connection/tls.c`, `src/protocols/root/session/protocol.c`, `src/net/upstream/tls.c`. | Parity | Also implemented for upstream proxy bootstrap when backend requires `kXR_gotoTLS`. |
| Signing (`kXR_sigver`) | `XrdSecProtect`, XrdXrootd signing enforcement. | `src/protocols/root/handshake/dispatch_signing.c`, signing enforcement before dispatch. | Parity | Module enforces configured signing level before handler dispatch. |
| Session bind / secondary streams | Upstream bind/session mechanisms. | `src/protocols/root/session/bind.c`, `src/protocols/root/session/registry.c`; read dispatch restricts bound streams to read-style handle I/O. | Parity | Bound stream write rejection is explicit in `dispatch_read.c`. |
| Open/read/close/stat | Upstream `do_Open`, file-handle read dispatch. | `src/protocols/root/read/open.c`, `src/protocols/root/read/read.c`, `src/close.c`, `src/stat.c`. | Parity | Path confinement is module-specific and stronger operationally. |
| Readv / writev | Upstream handle dispatch. | `src/protocols/root/read/readv.c`, `src/protocols/root/write/writev.c`. | Parity | Both support vector I/O. |
| Paged read/write with CRC32c | Upstream protocol has `kXR_pgread` and `kXR_pgwrite`; CRC helpers in `XrdOuc`. | `src/protocols/root/read/pgread.c`, `src/protocols/root/write/pgwrite.c`, `src/protocols/root/protocol/flags.h`; protocol advertises `kXR_suppgrw`. | Parity | Project invariant requires `kXR_status(4007)` framing and per-page CRC32c. |
| POSC | Upstream supports `kXR_posc` and `kXR_supposc`. | `src/protocols/root/read/open.c`, `src/protocols/root/connection/fd_table.c`, protocol advertises `kXR_supposc`. | Parity | Cleanup on failed/abandoned POSC is wired through handle free logic. |
| Namespace mutation: mkdir, rm, rmdir, mv, chmod, truncate | Upstream dispatches these in `XrdXrootdProtocol.cc`. | `src/mkdir.c`, `src/rm.c`, `src/protocols/root/write/mv.c`, `src/chmod.c`, `src/truncate.c`. | Parity | Module gates writes through global `allow_write` plus auth/token/ACL checks. |
| Extended attributes (`kXR_fattr`) | Upstream `do_FAttr`. | `src/protocols/root/fattr/`; read dispatcher routes `kXR_fattr`. | Parity | Module maps user-facing attrs through local xattrs and includes auth gating. |
| Locate / manager redirects | Upstream XrdCms/XrdXrootd integration. | `src/protocols/root/read/locate.c`, `src/net/manager/`, `src/net/cms/`, `src/net/upstream/`. | Partial | Practical redirector behavior exists; full upstream CMS admin/tooling is broader. |
| Query subtypes | Upstream `do_Query` and plugin hooks. | `src/protocols/root/query/` including checksum, config, space, prep, opaque. | Partial | Common operational queries are present. Full opaque/plugin semantics are narrower. |
| Prepare/stage (`kXR_prepare`, `kXR_QPrep`) | Upstream `do_Prepare` plus full `XrdFrm` ecosystem. | `src/protocols/root/query/prepare.c`, `src/frm/`, `src/protocols/webdav/tape_rest.c`. | Partial | This module now has a real durable queue and tape gateway, but not full upstream FRM daemon/admin/migrate/purge parity. |
| Checkpoint (`kXR_chkpoint`) | Upstream handle dispatch includes checkpoint. | `src/protocols/root/write/chkpoint.c`. | Parity | Write dispatcher routes checkpoint with write gate. |
| Clone (`kXR_clone`) | Upstream handle dispatch includes clone. | `src/protocols/root/read/clone.c`; read dispatcher routes `kXR_clone`. | Parity | Server-side range copy exists. |
| `kXR_gpfile` / GPF | Upstream defines and dispatches `gpfile`, but default handler returns `kXR_Unsupported`; upstream may advertise GPF only when filesystem features indicate support. | `kXR_gpfile` is defined but not dispatched; protocol never advertises `kXR_supgpf`/`kXR_anongpf`; tests assert they remain unset. | Not a practical gap | Correct behavior is to avoid advertising GPF unless implemented. The official default handler is also unsupported. |
| `kXR_ecRedir` | Protocol flag exists upstream. | Defined in `src/protocols/root/protocol/flags.h`, never set. | Missing / out of scope | Requires EC storage backend semantics not otherwise present here. |
| `kXR_recoverWrts` | Upstream client honors it; server semantics depend on write recovery support. | `src/protocols/root/write/wrts_journal.c`, `tests/test_recover_wrts.py`, `tests/test_write_recovery.py`; protocol flag set only when configured. | Partial | Implemented as per-handle idempotent write replay. Review semantics before advertising broadly at sites. |

## Authentication and Authorization

Source anchors:

- Upstream plugin directories:
  `/tmp/xrootd-src/src/XrdSec*`,
  `/tmp/xrootd-src/src/XrdMacaroons`,
  `/tmp/xrootd-src/src/XrdSciTokens`,
  `/tmp/xrootd-src/src/XrdVoms`
- nginx auth source:
  `src/auth/gsi/`, `src/auth/token/`, `src/auth/sss/`, `src/auth/unix/`, `src/auth/krb5/`,
  `src/auth/authz/authdb.c`, `src/auth/authz/acl.c`, `src/core/config/policy.c`

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| Anonymous mode | Core XRootD config/auth flow. | `xrootd_auth none`; login/session code. | Parity | Used heavily in tests and proxy/cache modes. |
| GSI / x509 proxy cert auth | `XrdSecgsi`, `XrdVoms`. | `src/auth/gsi/`, `src/auth/voms/`, WebDAV cert auth in `src/protocols/webdav/auth_cert.c`. | Parity | Module supports proxy certs and optional VOMS/VO authorization. |
| SSS | `XrdSecsss`. | `src/auth/sss/`; protocol advertises `sss`. | Parity | Standard encrypted keytab format support is documented and source-backed. |
| Unix auth | `XrdSecunix`. | `src/auth/unix/auth.c`; protocol advertises `unix` when configured. | Parity | Module is loopback-only by default unless `xrootd_unix_trust_remote on`. |
| Kerberos 5 | `XrdSeckrb5`. | `src/auth/krb5/auth.c`, `src/auth/krb5/config.c`; optional Kerberos detection in `config`. | Parity | Existing docs that call this absent are stale. |
| Bearer token / `ztn` | `XrdSecztn`; `XrdSciTokens`. | `src/auth/token/validate.c`, `src/auth/token/jwks.c`, `src/auth/token/scopes.c`; WebDAV bearer auth. | Partial | WLCG/JWT validation and path scopes exist. Upstream SciTokens has a broader helper/config/monitor model. |
| Macaroons | `XrdMacaroons` HTTP handlers and authz. | `src/auth/token/macaroon.c`, `src/auth/token/macaroon_issue.c`, `src/protocols/webdav/macaroon_endpoint.c`. | Partial | Validation, caveats, third-party discharge bundles, and token endpoint exist. Review wire-format compatibility if claiming exact `XrdMacaroons` parity. |
| Password auth | `XrdSecpwd` and `xrdpwdadmin`. | `src/auth/pwd/auth.c` + `src/auth/pwd/pwdfile.c`; 2-round DH-bootstrapped handshake, opt-in `xrootd_auth pwd` + `xrootd_pwd_file`. | Partial / parity | Wire-equivalent of `XrdSecpwd`; not the full `xrdpwdadmin`/server-public-key admin ecosystem. Recommended under TLS. |
| Host auth | Built-in `host` protocol in `XrdSec` (`XrdSecProtocolhost.cc`). | `src/auth/host/auth.c`; reverse-DNS allowlist, opt-in `xrootd_auth host` + `xrootd_host_allow`. | Parity | Identity from socket reverse-DNS only; fail-closed, trusted-network only by design. |
| Full `XrdAcc` authdb semantics | `XrdAcc` supports rich auth-file syntax and identities. | `src/auth/authz/authdb.c` supports user/group/principal/host rules, longest-prefix matching, and rw/admin-like privilege bits. | Partial | Good practical authdb, not full `XrdAcc` semantics such as all upstream identity classes/templates/exclusive-list behavior. |
| Token scope authorization | Upstream SciTokens maps token claims to XrdAcc privileges. | `src/auth/token/scopes.c`, `src/auth/authz/auth_gate.c`, WebDAV token checks. | Partial / nginx+ | Scope enforcement is explicit and path-boundary aware; upstream configurability is broader. |
| Global write gate before token scope | Upstream policy depends on configured authz stack. | `xrootd_allow_write` and WebDAV/common write gates. | nginx+ | Useful operational safety: global write enablement remains a precondition. |
| Request signing/security levels | Upstream XrdSec protection. | `src/protocols/root/handshake/dispatch_signing.c`, `src/protocols/root/session/protocol.c`. | Parity | SecurityInfo trailer advertises configured signing level. |

## HTTP, WebDAV, XrdHttp, HTTP-TPC, and S3

Source anchors:

- Upstream HTTP:
  `/tmp/xrootd-src/src/XrdHttp`,
  `/tmp/xrootd-src/src/XrdHttpTpc`,
  `/tmp/xrootd-src/src/XrdHttpCors`
- nginx HTTP:
  `src/protocols/webdav/`, `src/protocols/s3/`

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| XrdHttp core methods | `XrdHttpReq.hh`/`.cc` support `GET`, `HEAD`, `PUT`, `OPTIONS`, `DELETE`, `PROPFIND`, `MKCOL`, `MOVE`, and `COPY`. | `src/protocols/webdav/dispatch.c`, `src/protocols/webdav/get.c`, `put.c`, `namespace.c`, `move.c`, `copy.c`, `propfind.c`. | Parity | Older docs saying XrdHttp is absent are stale. |
| XrdHttp headers/dialect | Upstream `XrdHttp` implements XRootD-over-HTTP behavior. | `src/protocols/webdav/xrdhttp.c`, `xrdhttp_filter.c`, `xrdhttp_stats.c`, checksum/header helpers. | Parity | Module implements `X-Xrootd-*` headers, status translation, `?xrd.stats`, digest/checksum, and redirect dialect. |
| HTTP range and multipart GET | Upstream XrdHttp has range handling. | `src/protocols/webdav/get.c` and XrdHttp/WebDAV range handling. | Parity | Cleartext can use file-backed buffers/sendfile; TLS uses memory-backed buffers. |
| CORS | Upstream optional `XrdHttpCors`. | `webdav_add_cors_headers()` and S3/WebDAV CORS paths. | Parity | Module exposes CORS through helpers and low-cardinality metrics. |
| HTTP-TPC | Upstream `XrdHttpTpc` supports COPY, multistream, PMark manager, curl-based outbound HTTP. | `src/protocols/webdav/tpc.c`, `tpc_curl.c`, `tpc_marker.c`, `tpc_cred.c`, `tpc_headers.c`. | Parity / nginx+ | Upstream has HTTP-TPC; nginx adds operational integration, SSRF/DNS-pinning hardening, dashboard visibility, and credential-delegation options. |
| HTTP-TPC performance markers | `XrdHttpTpcPMarkManager.cc`. | `src/protocols/webdav/tpc_marker.c`, marker interval directive. | Parity | Both implement marker-style transfer progress. |
| HTTP-TPC multistream | `XrdHttpTpcMultistream.cc`; test script uses `X-Number-Of-Streams`. | `src/protocols/webdav/tpc_curl.c` parallel Range GET via `curl_multi`; capped by configured max streams. | Parity | nginx implementation should be described as comparable, not unique. |
| OAuth/OIDC TPC credential delegation | Upstream supports credential handling through XrdHttpTpc mechanisms. | `src/protocols/webdav/tpc_cred.c` supports `oidc-agent` and RFC 8693 token exchange. | nginx+ / Partial | This is a strong operational feature; exact upstream parity depends on credential mode. |
| WebDAV `LOCK` / `UNLOCK` | No server method enum found in `XrdHttpReq.hh`; upstream has HTTP 423 status code but not full LOCK handlers in reviewed source. | `src/protocols/webdav/lock.c`, xattr lock storage, recursive child lock checks. | nginx+ | Important for desktop WebDAV clients. |
| WebDAV `PROPPATCH` and dead properties | No upstream server method enum found in reviewed XrdHttp source. | `src/protocols/webdav/methods_basic.c`, `src/protocols/webdav/dead_props.c`, xattr storage. | nginx+ | Enables clients that treat `501` on PROPPATCH as fatal. |
| WebDAV `SEARCH` | No upstream server method enum found in reviewed XrdHttp source. | `src/protocols/webdav/search.c`. | nginx+ | Basic RFC 5323 discovery over confined namespace. |
| WebDAV `ACL` method | No upstream server method enum found in reviewed XrdHttp source. | `src/protocols/webdav/acl.c`; protected mutation response. | nginx+ | Exposes discovery semantics while refusing client-side ACL mutation. |
| WebDAV proxy mode | Upstream can proxy via XRootD/PSS style services, not nginx HTTP reverse proxy semantics. | `src/protocols/webdav/proxy.c`, `proxy_pool.c`, `proxy_config.c`. | nginx+ | HTTP backend pools, TLS, auth bridging, and Destination rewrite are nginx-native. |
| S3 server endpoint | Upstream has `XrdClS3`, a client plugin; no server-side S3 REST endpoint found in `/tmp/xrootd-src/src`. | `src/protocols/s3/handler.c`, `auth_sigv4_*`, `get.c`, `put.c`, `list_objects_v2.c`, `multipart_*`, `copy.c`, `delete_objects.c`, browser POST. | nginx+ | This is one of the strongest module-only features. |
| S3 SigV4 | Upstream `XrdClS3` signs client requests. | `src/protocols/s3/auth_sigv4_parse.c`, `auth_sigv4_canonical.c`, `auth_sigv4_verify.c`. | nginx+ | Server-side verification includes header and presigned query forms. |
| S3 multipart | Upstream client can speak S3; no upstream server endpoint. | `src/protocols/s3/multipart*.c`. | nginx+ | Create, upload part, complete, abort, list parts/uploads, upload-part-copy. |
| S3 advanced REST compatibility | No upstream server endpoint found. | Batch delete, CopyObject, POST Object, OPTIONS/CORS, ListObjectsV2 subset. | nginx+ | Still path-style focused; virtual-hosted buckets and dynamic STS stores remain out of scope per docs. |

## Storage, Cache, Tape, and Backend Ecosystem

Source anchors:

- Upstream optional subsystems:
  `/tmp/xrootd-src/src/XrdCeph`,
  `/tmp/xrootd-src/src/XrdPss`,
  `/tmp/xrootd-src/src/XrdPfc`,
  `/tmp/xrootd-src/src/XrdOssCsi`,
  `/tmp/xrootd-src/src/XrdFrm`,
  `/tmp/xrootd-src/src/XrdZip`,
  `/tmp/xrootd-src/src/XrdRmc`
- nginx storage source:
  `src/fs/`, `src/path/`, `src/fs/cache/`, `src/frm/`,
  `src/core/compat/namespace_ops.c`

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| POSIX local filesystem serving | Core `XrdOss`/`XrdSfs` stack. | Local POSIX operations through confined path helpers, namespace ops, fd table, sendfile/mmap-style HTTP paths. | Parity | This module is intentionally strongest as a POSIX-backed data server/gateway. |
| Path confinement and symlink escape defense | Upstream has its own namespace and auth mechanisms. | `src/path/`, `src/core/compat/namespace_ops.c`, `ngx_http_xrootd_webdav_resolve_path()`, `xrootd_open_confined_canon()`. | nginx+ | All wire paths should resolve before syscall; this is a major auditability advantage. |
| Read-through cache / XCache-style role | Upstream `XrdPfc`, `XrdRmc`, cache plugins. | `src/fs/cache/`, `src/open_cache.c`, protocol `kXR_attrCache`. | Partial | Practical cache mode exists. Upstream `XrdPfc` has much broader policy, purge, snapshot, and resource-monitoring machinery. |
| Parallel Storage Service | `XrdPss` plugin. | No comparable PSS backend found. | Missing | Important for sites using remote federation/cache-fill as their storage layer. |
| Ceph/RADOS backend | `XrdCeph` plugin. | No comparable Ceph OSS backend found. | Missing | Could be handled through POSIX/CephFS externally, but not through an XRootD-style Ceph plugin. |
| Checksum/tagstore storage | `XrdOssCsi` page checksum/tagstore implementation. | File-level checksum helpers and xattr-cached integrity; no comparable `XrdOssCsi` tagstore found. | Missing / Partial | Paged wire CRC exists; persistent checksum-index/tagstore parity does not. |
| XrdFrm | Full `XrdFrm` static library plus `frm_admin`, `frm_purged`, `frm_xfrd`, `frm_xfragent`, migrate, purge, transfer queue. | `src/frm/` durable queue, residency xattrs, stage worker, scheduler, metrics, Tape REST, async/wait paths. | Partial | This module has a serious tape gateway, not the whole upstream FRM daemon/admin ecosystem. |
| WLCG Tape REST | Not a core XRootD daemon feature in the reviewed source tree. | `src/protocols/webdav/tape_rest.c`. | nginx+ | Gives FTS/gfal2-friendly HTTP tape operations tied to the same durable FRM queue. |
| Migrate/purge policy engine | Upstream `XrdFrmMigrate`, `XrdFrmPurge`, purged daemon. | `src/frm/migrate_purge.c` scaffold/stub per docs. | Missing / Partial | Keep as a serious reviewer item for tape sites requiring disk-to-tape migration or watermark GC inside this process. |
| External tape/MSS driver abstraction | Upstream has MSS/ARC/Frm-style abstractions and daemon workflows. | Operator `copycmd`/`residency_cmd`; no linked tape library. | Partial | Simpler and auditable, but not drop-in for sites depending on upstream MSS plugins. |
| Zip archive support | `XrdZip` source exists. | `src/protocols/root/zip/` — pure-C central-directory reader (`zip_dir.c`), `zip_member.c`, HTTP member serving (`zip_http.c`), wired into the build. | Partial | ZIP-member access over HTTP exists; not full upstream cross-protocol parity. |
| Remanufactured memory cache | `XrdRmc` source exists. | No comparable `XrdRmc` implementation found. | Missing | Mostly a specialized upstream cache feature. |
| Checksum plugin framework | Upstream `XrdCks` plugin mapping supports deployment-specific checksum modules. | `src/core/compat/checksum.c` supports common algorithms including adler32/crc32/crc32c/md5/sha1/sha256 plus CRC-64/XZ and CRC-64/NVME via `src/core/compat/crc64.c`. | Partial / nginx+ for CRC64 | Full plugin-framework parity is still narrower; CRC64 itself is implemented. |
| Client libraries/tools | Upstream ships `XrdCl`, `XrdPosix`, FUSE/tooling. | Not applicable to server module. | Not replacement-scope | This module replaces server behavior, not the upstream client SDK ecosystem. |

## Cluster, Redirector, Proxy, and TPC

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| Data server role | Core XrdXrootd. | `kXR_isServer` always set. | Parity | Module is a data server by default. |
| Manager / redirector | `XrdCms`, XrdXrootd manager integration. | `src/net/manager/`, `src/net/cms/`, `src/protocols/root/read/locate.c`, `src/net/upstream/`. | Partial | Practical locate/redirect and manager mode exist. Upstream CMS has broader tooling and battle-tested semantics. |
| Supervisor/meta manager role | Upstream flags/roles. | `xrootd_supervisor`, `kXR_attrSuper`, tests. | Parity / Partial | Flagging exists; ensure topology behavior matches target deployment before marketing full CMS parity. |
| Virtual redirector | Upstream protocol clients understand `kXR_attrVirtRdr`. | `xrootd_virtual_redirector` and auto-detection for static manager maps. | nginx+ / Partial | Useful nginx-specific static map deployment mode. |
| Collapse redirects | Upstream has client/server redirect mechanics. | `src/net/manager/redir_cache.c`; `kXR_collapseRedir` when configured. | nginx+ / Partial | Implemented as SHM redirect-target cache. |
| Native TPC / clone | Upstream native TPC and clone behavior. | `src/tpc/`, `src/protocols/root/read/clone.c`. | Parity / Partial | Module has SHM key registry and clone; verify multi-hop/TLS/delegation edge cases per site. |
| HTTP-TPC | `XrdHttpTpc`. | `src/protocols/webdav/tpc*.c`. | Parity / nginx+ | See HTTP table. |
| Upstream proxy mode | Upstream has PSS/proxy/cache architectures. | `src/net/proxy/`, `src/net/upstream/`, `src/protocols/webdav/proxy.c`. | nginx+ / Partial | nginx offers protocol bridge and HTTP reverse proxy features; some upstream async edge cases remain flagged. |
| Traffic mirroring / shadow validation | No comparable upstream server feature found. | `src/net/mirror/`, `src/net/mirror/stream_wmirror.c`, phase-24 tests/docs. | nginx+ | Strong migration feature: run shadow paths before cutover and track divergence. |
| Dynamic upstream pools and health | Upstream CMS and PSS ecosystems. | `src/net/upstream/`, WebDAV proxy backend pools, manager registry. | Partial / nginx+ | Strong for nginx-style operations, not a CMS toolchain clone. |

## Observability and Operations

| Feature | Upstream XRootD source | nginx-xrootd source | Status | Notes |
|---|---|---|---|---|
| UDP XrdMon stream monitoring | Upstream `XrdXrootdMon*` / XrdMon ecosystem. | Not implemented. | Not counted | Explicit product decision: do not implement. Use HTTP-native observability instead. |
| Prometheus metrics | Upstream has some HTTP/monitoring counters but UDP monitoring is historical primary grid surface. | `src/observability/metrics/`, `/metrics`, low-cardinality counters across stream/WebDAV/S3/rate-limit/cache/FRM/mirror. | nginx+ | Primary replacement for UDP monitoring. |
| WLCG Storage Resource Reporting | Not a core upstream replacement surface in reviewed source. | `src/protocols/srr/`. | nginx+ | Useful for site accounting/discovery. |
| Live transfer dashboard | Upstream has admin tools and monitoring ecosystem. | `src/observability/dashboard/`, `/xrootd/api/v1/transfers`, events, history, cluster, cache, ratelimit, config. | nginx+ | Operator-friendly visibility built into the server. |
| Admin API | Upstream admin commands/tools. | `src/observability/dashboard/api_admin.c`, auth/cookie/HMAC paths. | nginx+ / Partial | Different operational model; not drop-in for XRootD admin command tooling. |
| Access logs | Upstream logs and monitor streams. | nginx access/error logs plus protocol-specific logs and sanitized wire strings. | nginx+ | Fits existing nginx observability/log shipping. |
| Rate limiting / bandwidth / concurrency | Upstream `XrdThrottle` and `XrdBwm`. | `src/net/ratelimit/`, `xrootd_rate_limit_zone`, `xrootd_rate_limit_rule`, `xrootd_bandwidth_limit`, `xrootd_concurrency_limit`. | Parity / nginx+ | Upstream has throttle/BWM plugins; nginx implementation is cross-protocol and identity-aware. |
| IPv6 completion and low-cardinality metrics | Upstream supports IPv6 at core network layer. | Phase-36 docs/tests cover stream, CMS redirect, WebDAV/XrdHttp, S3, TPC, admin, rate-limit, metrics. | Parity / nginx+ | Reviewer should prefer source/tests over stale docs where IPv6 gaps are mentioned. |
| Packet marking / SciTags / PMark | Upstream has `XrdNetPMark`, XrdHttp PMark, XrdHttpTpc PMark manager. | `src/observability/pmark/`, WebDAV/TPC integration, optional HTTP plain marking. | Partial / Parity | Both ecosystems have packet marking; implementation surfaces differ. |

## nginx-only or nginx-forward Features

These are the features that make the replacement case stronger than a simple
"same protocol in another daemon" argument.

| Feature | Source evidence | Why it matters |
|---|---|---|
| S3-compatible server endpoint | `src/protocols/s3/` | Lets sites expose the same namespace to S3 clients without a separate gateway or data copy. Upstream has `XrdClS3` client code, not an S3 REST server in the reviewed tree. |
| Unified multi-protocol namespace | `src/protocols/root/read/`, `src/protocols/webdav/`, `src/protocols/s3/`, shared path/auth helpers | One export can serve `root://`, `davs://`/XrdHttp, and S3-style clients with common confinement and policy rules. |
| Prometheus-first monitoring | `src/observability/metrics/`, `src/observability/dashboard/`, `src/protocols/srr/` | Avoids UDP monitoring while integrating with modern site monitoring stacks. |
| Dashboard/admin API | `src/observability/dashboard/` | Makes transfer, cluster, cache, rate-limit, and config state inspectable over HTTP. |
| Identity-aware shaping | `src/net/ratelimit/` | Applies request-rate, bandwidth, and concurrency controls by VO, issuer, DN hash, IP, or volume prefix across stream and HTTP. |
| WebDAV desktop/client compatibility | `src/protocols/webdav/lock.c`, `dead_props.c`, `search.c`, `acl.c` | Supports clients that need locks or dead properties, beyond upstream XrdHttp's reviewed method set. |
| Hardened HTTP-TPC | `src/protocols/webdav/tpc_curl.c`, `tpc_cred.c`, `tpc_marker.c` | Adds SSRF/DNS pinning, credential exchange, marker streaming, multistream, and metrics in one module. |
| Traffic mirroring | `src/net/mirror/` | Enables safe site migration by shadowing reads/writes and logging divergence before cutover. |
| Path confinement discipline | `src/path/`, `src/core/compat/namespace_ops.c` | Makes the codebase auditable: resolve/canonicalize/confine first, then syscall. |
| WLCG Tape REST gateway | `src/protocols/webdav/tape_rest.c`, `src/frm/` | Provides modern HTTP tape control while sharing the same stage queue as native XRootD prepare/open. |
| nginx TLS/logging/reload model | nginx module integration through top-level `config` | Sites can reuse nginx operational practices for certs, reloads, logging, HTTP routing, and reverse proxying. |

## Missing or Incomplete Upstream Features That Matter

These are the real replacement blockers or due-diligence items after excluding
UDP monitoring.

| Gap | Upstream evidence | nginx evidence | Impact | Suggested position |
|---|---|---|---|---|
| `pwd` authentication | `/tmp/xrootd-src/src/XrdSecpwd` | **Implemented** — `src/auth/pwd/` (DH-bootstrapped handshake). | No longer a blocker; wire-equivalent, not the full `xrdpwdadmin` admin ecosystem. | Closed; advertise as available legacy scheme (TLS recommended). |
| `host` authentication | `/tmp/xrootd-src/src/XrdSec/XrdSecProtocolhost.cc` | **Implemented** — `src/auth/host/` (reverse-DNS allowlist). | No longer a blocker for trusted-network deployments. | Closed; advertise as fail-closed, trusted-network only. |
| Full `XrdAcc` compatibility | `/tmp/xrootd-src/src/XrdAcc` | `src/auth/authz/authdb.c` implements a narrower authdb. | Complex existing auth files may need translation. | Build a migration guide or converter rather than cloning all `XrdAcc`. |
| Full SciTokens plugin semantics | `/tmp/xrootd-src/src/XrdSciTokens` | `src/auth/token/` validates WLCG/JWT and scopes. | Sites using advanced issuer/config/helper behavior need review. | Document supported claims/scopes precisely. |
| Full `XrdFrm` daemon/admin ecosystem | `/tmp/xrootd-src/src/XrdFrm` | `src/frm/` plus Tape REST; migrate/purge scaffold. | Tape sites with upstream FRM operational workflows are not drop-in. | Present as functional tape gateway, not complete FRM clone. |
| PSS backend | `/tmp/xrootd-src/src/XrdPss` | No comparable implementation found. | Sites using PSS for remote storage access need another architecture. | Use proxy/cache/gateway patterns where possible; do not claim parity. |
| PFC/XCache full policy cache | `/tmp/xrootd-src/src/XrdPfc` | `src/fs/cache/` is narrower. | Sites relying on PFC purge/snapshot/policy internals need review. | Claim cache support, not full PFC parity. |
| Ceph plugin | `/tmp/xrootd-src/src/XrdCeph` | No plugin-level Ceph backend. | Ceph/RADOS-backed XRootD sites need POSIX/CephFS or a new backend. | Out of scope unless a target site requires it. |
| XrdOssCsi tagstore/checksum store | `/tmp/xrootd-src/src/XrdOssCsi` | No comparable tagstore. | Persistent checksum/page-integrity workflows may differ. | Treat as storage-plugin gap. |
| Checksum plugin framework breadth | `/tmp/xrootd-src/src/XrdCks`, `XrdVersionPlugin.hh` | Fixed local checksum set with CRC64/CRC64NVME included. | Compatibility gap only for uncommon site-specific checksum plugins. | Add plugins only if needed by site validation. |
| ZIP virtual filesystem | `/tmp/xrootd-src/src/XrdZip` | **Partially implemented** — `src/protocols/root/zip/` (central-dir reader + HTTP member serving). | ZIP-member access over HTTP exists; full cross-protocol parity does not. | Mostly closed; validate breadth if a site needs full ZIP-member semantics. |
| CMS admin/tooling completeness | `/tmp/xrootd-src/src/XrdCms` | `src/net/cms/`, `src/net/manager/` implement practical manager behavior. | Complex multi-tier production clusters may need careful conformance testing. | Claim manager/redirector support with caveats. |
| Proxy async `kXR_waitresp`/`kXR_attn` relay | Upstream client/server supports async responses. | `src/net/upstream/response.c` forwards `kXR_waitresp`; no complete unsolicited upstream `kXR_attn` path was verified in this pass. | Could affect proxying to backends that park operations. | Keep as serious proxy-mode gap until source/test proves closure. |
| Proxy `kXR_prepare` path-list rewrite | Upstream prepare supports path lists. | Existing proxy docs flag whole-payload rewrite behavior. | Path mapping proxy deployments may mishandle multi-path prepare. | Keep as serious gap unless tests/source show per-entry rewrite. |
| Erasure-coded redirects (`kXR_ecRedir`) | Protocol flag and client handling exist upstream. | Defined, never set. | EC storage redirect semantics not present. | Out of scope without EC backend. |

## Claims That Can Safely Be Made

Source-backed claims suitable for a review or position paper:

- This module implements the practical native XRootD data-server opcode set,
  including v5-era paged I/O, clone, signing, TLS negotiation, POSC, vector I/O,
  extended attributes, prepare/QPrep, and manager/redirect responses.
- It deliberately does not implement UDP XrdMon monitoring; instead it exposes
  first-class Prometheus, SRR, dashboard, access-log, and admin API surfaces.
- It adds an S3-compatible server endpoint that upstream XRootD does not provide
  in the reviewed source tree.
- It supports HTTP/WebDAV/XrdHttp and HTTP-TPC; upstream also supports XrdHttp
  and XrdHttpTpc, so nginx's advantage is integration, hardening, and
  operations, not the mere existence of HTTP-TPC.
- It implements every standard upstream stream auth scheme: GSI, VOMS, SSS,
  Unix, Kerberos, WLCG/JWT tokens, scopes, macaroons, and now `pwd` and `host`.
  Only *custom* third-party sec plugins (no loadable sec-plugin ABI) remain out
  of reach.
- It is a focused, auditable POSIX-backed server/gateway with stronger nginx
  operational ergonomics, not a clone of every upstream storage plugin.

Claims to avoid or qualify:

- Do not claim upstream XRootD lacks HTTP-TPC.
- Do not claim this module has full `XrdFrm` parity; say it has a durable
  FRM-style staging queue and WLCG Tape REST gateway.
- Do not claim full `XrdAcc`, `XrdPfc`, `XrdPss`, `XrdCeph`, or `XrdOssCsi`
  parity.
- Do not list `krb5`, `unix`, XrdHttp, rate limiting, protocol role flags, or
  macaroon delegation as missing without re-checking current source.
- Do not count UDP monitoring as a missing feature in this review; it is an
  explicit non-goal.

## Suggested Review Framing

For a site review, the replacement argument should be framed around operational
fit:

1. If the site primarily serves POSIX-backed data over `root://` and `davs://`,
   and wants Prometheus/S3/dashboard/rate-limit/TLS/nginx operations, this
   module offers a strong replacement candidate with additional modern surfaces.
2. If the site depends on historical XRootD plugin ecosystems, especially PSS,
   PFC, Ceph, full FRM daemons, UDP monitoring, complex `XrdAcc`, or legacy
   `pwd`/`host` auth, migration requires either explicit compatibility work or
   an architecture change.
3. The correct proof point is not "feature list says yes"; it is a site-specific
   conformance matrix with three tests per changed or critical feature:
   success, error, and security-negative.

## Evidence Appendix

High-signal source files inspected for this comparison:

| Area | nginx-xrootd | Official XRootD |
|---|---|---|
| Protocol opcodes/flags | `src/protocols/root/protocol/opcodes.h`, `src/protocols/root/protocol/flags.h`, `src/protocols/root/session/protocol.c` | `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` |
| Dispatch | `src/protocols/root/handshake/dispatch*.c` | `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdProtocol.cc`, `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeq.cc` |
| Auth | `src/auth/gsi/`, `src/auth/token/`, `src/auth/sss/`, `src/auth/unix/`, `src/auth/krb5/`, `src/auth/authz/authdb.c` | `/tmp/xrootd-src/src/XrdSec*`, `/tmp/xrootd-src/src/XrdMacaroons`, `/tmp/xrootd-src/src/XrdSciTokens`, `/tmp/xrootd-src/src/XrdVoms`, `/tmp/xrootd-src/src/XrdAcc` |
| HTTP/WebDAV/XrdHttp | `src/protocols/webdav/` | `/tmp/xrootd-src/src/XrdHttp`, `/tmp/xrootd-src/src/XrdHttpCors` |
| HTTP-TPC | `src/protocols/webdav/tpc*.c` | `/tmp/xrootd-src/src/XrdHttpTpc` |
| S3 | `src/protocols/s3/` | `/tmp/xrootd-src/src/XrdClS3` |
| Cache/storage | `src/fs/cache/`, `src/fs/`, `src/path/`, `src/core/compat/namespace_ops.c` | `/tmp/xrootd-src/src/XrdPfc`, `/tmp/xrootd-src/src/XrdPss`, `/tmp/xrootd-src/src/XrdCeph`, `/tmp/xrootd-src/src/XrdOssCsi`, `/tmp/xrootd-src/src/XrdZip`, `/tmp/xrootd-src/src/XrdRmc` |
| FRM/tape | `src/frm/`, `src/protocols/root/query/prepare.c`, `src/protocols/webdav/tape_rest.c` | `/tmp/xrootd-src/src/XrdFrm` |
| Rate limiting | `src/net/ratelimit/`, `src/observability/metrics/ratelimit.c` | `/tmp/xrootd-src/src/XrdThrottle`, `/tmp/xrootd-src/src/XrdBwm` |
| CMS/manager/proxy | `src/net/cms/`, `src/net/manager/`, `src/net/upstream/`, `src/net/proxy/` | `/tmp/xrootd-src/src/XrdCms`, `/tmp/xrootd-src/src/XrdXrootd` |
| Observability | `src/observability/metrics/`, `src/observability/dashboard/`, `src/protocols/srr/` | `/tmp/xrootd-src/src/XrdMon`, `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdMon*` |
| Migration/mirroring | `src/net/mirror/` | No comparable upstream server subsystem found in reviewed source. |
