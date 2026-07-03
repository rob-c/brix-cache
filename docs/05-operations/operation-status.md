# Implementation status

How BriX-Cache stacks up against the official `xrootd` data-server surface,
operation by operation. Use this before reporting a missing feature, planning a
migration, or deciding what to work on next.

---

## Protocol version

The module advertises **XRootD protocol version 0x00000520** (5.2.0) in the
`kXR_protocol` response. This is a wire-protocol version, not the upstream
XRootD software release number. Current XRootD software releases are newer 5.x
and 6.x packages while still retaining compatibility with the 5.2 protocol
surface used here.

---

## Opcode coverage

All 33 standard client opcode numbers in the 5.2 protocol table are recognized:
32 have current data-server behavior and the legacy `kXR_gpfile` opcode is
explicitly rejected with `kXR_Unsupported`.

### Fully implemented

| Opcode | Value | Notes |
|---|---|---|
| `kXR_auth` | 3000 | GSI (x509/proxy), JWT/WLCG bearer token (`ztn`), anonymous |
| `kXR_query` | 3001 | Subtypes: Qcksum, Qspace, Qconfig, QStats, Qxattr, QFinfo, QFSinfo, plus reference-compatible Qvisa/Qopaque/Qopaquf/Qopaqug hooks |
| `kXR_chmod` | 3002 | |
| `kXR_close` | 3003 | Logs per-handle bytes and elapsed time |
| `kXR_dirlist` | 3004 | Supports `kXR_dstat` per-entry stat, `kXR_dcksm` per-entry checksums, and chunked `kXR_oksofar` responses |
| `kXR_protocol` | 3006 | Security info, TLS capability advertisement, signing requirements |
| `kXR_login` | 3007 | Session ID, GSI challenge, token challenge |
| `kXR_mkdir` | 3008 | Recursive with `kXR_mkdirpath` / `kXR_mkpath` |
| `kXR_mv` | 3009 | |
| `kXR_open` | 3010 | `kXR_retstat`, create/overwrite/append modes, `kXR_posc`, `kXR_mkpath` |
| `kXR_ping` | 3011 | |
| `kXR_chkpoint` | 3012 | Begin / commit / rollback / query / xeq; checkpoint stored as sibling `.ckp` file; `kXR_ckpXeq` supports write, pgwrite, truncate, writev sub-ops |
| `kXR_read` | 3013 | Chunked `kXR_oksofar`; cleartext regular files can use file-backed send chains, other paths can use thread-pool reads |
| `kXR_rm` | 3014 | |
| `kXR_rmdir` | 3015 | |
| `kXR_sync` | 3016 | fsync on open handle |
| `kXR_stat` | 3017 | Path-based and handle-based |
| `kXR_set` | 3018 | `appid` and `clttl` modifiers; unknown modifiers accepted as no-op |
| `kXR_write` | 3019 | Async via nginx thread pool |
| `kXR_fattr` | 3020 | get / set / del / list; backed by Linux xattrs (`user.U.*` namespace) |
| `kXR_prepare` | 3021 | Path validation + existence check. With `brix_frm on` (Phase 35): durable stage-request queue — real host-qualified reqid, `kXR_cancel` deletes the request, records survive disconnect + restart (`src/fs/xfer/`). `kXR_evict` accepted as a no-op (backend-delegated). Default (FRM off): legacy fire-and-forget `prepare_command`. |
| `kXR_statx` | 3022 | Multi-path stat (path list in payload) |
| `kXR_endsess` | 3023 | Graceful session termination |
| `kXR_bind` | 3024 | Secondary streams, pathid 1–253; inherits primary auth state |
| `kXR_readv` | 3025 | Scatter-gather up to 1024 segments; async via thread pool |
| `kXR_pgwrite` | 3026 | Per-page CRC32c validation; 32-byte `kXR_status` response |
| `kXR_locate` | 3027 | Wildcard (`*`), manager-map redirect, local reply, upstream delegation |
| `kXR_truncate` | 3028 | Path-based and handle-based |
| `kXR_sigver` | 3029 | HMAC-SHA256 envelope; replay (seqno) guard; RSA-signed pass-through |
| `kXR_pgread` | 3030 | Per-page CRC32c; async via thread pool |
| `kXR_writev` | 3031 | Scatter-gather multi-handle vector write |
| `kXR_clone` | 3032 | Server-side range copy; up to 1024 copy items per request; `copy_file_range(2)` with pread/pwrite fallback |

### Not implemented

| Opcode | Value | Priority | Notes |
|---|---|---|---|
| `kXR_gpfile` | 3005 | None | Legacy get/put (deprecated since protocol v3; no known live client uses it) |

Returns `kXR_Unsupported`.

### Upstream-declared but unimplemented request codes

The upstream XRootD protocol header (`src/XProtocol/XProtocol.hh` in a reference
`xrootd` tree) declares several request codes that are reserved, historical
aliases, or protocol-only entries and do not have active server-side handlers
in the reference `xrootd` source. For completeness, these are listed here to
avoid confusion when comparing protocol definitions:

- `kXR_1stRequest` (marker/alias)
- `kXR_admin`
- `kXR_decrypt`
- `kXR_getfile`
- `kXR_putfile`
- `kXR_REQFENCE` (marker / fence sentinel)
- `kXR_verifyw`

These codes are part of the protocol declaration but are not implemented as
request handlers in the upstream `xrootd` source tree and therefore are not
treated as supported opcodes by this module.

---

## Authentication

| Mechanism | Status | Notes |
|---|---|---|
| Anonymous | ✅ | Default; any username accepted |
| GSI / x509 proxy certificates | ✅ | Full DH key exchange, RFC 3820 proxy chain, VOMS attribute extraction |
| JWT / WLCG bearer tokens (`ztn`) | ✅ | JWKS validation, scope and group parsing |
| Mixed (`both`) | ✅ | Accepts either GSI or token on the same listener |
| SSS (Simple Shared Secrets) | ✅ | `brix_auth sss` + `brix_sss_keytab`; keytab uses the standard XRootD BF32-encrypted format; identity fields (user, group, name) extracted and logged |
| krb5 | ✅ | Optional build-time Kerberos 5 support in `src/auth/krb5`; availability depends on build dependencies/configuration. |
| pwd | ✅ | `brix_auth pwd` + `brix_pwd_file`; 2-round DH-bootstrapped password handshake (`src/auth/pwd/`). Legacy; run under TLS. Wire-equivalent, not the `xrdpwdadmin` admin ecosystem. |
| host | ✅ | `brix_auth host` + `brix_host_allow`; reverse-DNS allowlist (`src/auth/host/`). Legacy; fail-closed, trusted-network only. |

**Token scope enforcement**

| Scope | Required for (native `root://` path-resolving ops) | Notes |
|---|---|---|
| `storage.read` | `kXR_open` (read mode), `kXR_stat`, `kXR_dirlist`, `kXR_locate`, `kXR_statx`, `kXR_fattr` (get/list), `kXR_prepare` | Read access required for path resolution and metadata operations. |
| `storage.write` / `storage.create` | `kXR_open` (write/create mode), `kXR_mkdir`, `kXR_rm`, `kXR_rmdir`, `kXR_mv`, `kXR_chmod`, `kXR_truncate`, `kXR_fattr` (set/del), TPC pull destinations | Write/create access for operations that modify namespace or file data. |

- Handle-based I/O (e.g. `kXR_read`, `kXR_write`, `kXR_pgread`, `kXR_pgwrite`) inherits the scope decision from the `kXR_open` that produced the handle.
- `brix_allow_write` is an additional server-wide write gate that applies to all sessions regardless of auth method.
- Scope enforcement described above applies to native XRootD (`root://`) path-resolution and handle semantics; WebDAV (`davs://`) enforcement is handled separately and is fully implemented.

---

## TLS

| Mode | Status | Notes |
|---|---|---|
| In-protocol TLS upgrade (`kXR_wantTLS`) | ✅ | Upgrades a plain `root://` connection after `kXR_protocol` |
| `roots://` (nginx stream SSL from byte 0) | ✅ | Via `listen ... ssl` on the stream block |
| `davs://` (HTTP TLS for WebDAV) | ✅ | Via the HTTP module |
| S3-compatible HTTPS | ✅ | Same nginx HTTP SSL layer as WebDAV; S3 auth remains SigV4, not GSI/JWT |

See [tls.md](../03-configuration/tls-config.md) for configuration details.

---

## Query subtypes (`kXR_query`)

| Subtype | Value | Status |
|---|---|---|
| `kXR_QStats` | 1 | ✅ Server-wide operation counters |
| `kXR_QPrep` | 2 | ✅ Per-file availability status; `A <path>` (on disk) or `M <path>` (missing/unauthorized) per line. With `brix_frm on`, a not-yet-resident file with a live queue record reports `q`/`s`/`f` (queued/staging/failed) and the request id is durable (not `"0"`); FRM off keeps the legacy `"0"` reqid + stat-only `A`/`M`. |
| `kXR_Qcksum` | 3 | ✅ adler32, crc32c, md5, sha1, sha256 |
| `kXR_Qxattr` | 4 | ✅ Extended attributes (legacy path; prefer `kXR_fattr`) |
| `kXR_Qspace` | 5 | ✅ Filesystem free/total via `statvfs` |
| `kXR_Qckscan` | 6 | ✅ Bounded batch checksum scan of a file or directory tree |
| `kXR_Qconfig` | 7 | ✅ Key-value server configuration queries |
| `kXR_Qvisa` | 8 | ✅ Recognized handle-based fctl hook; returns the reference-compatible unsupported response when no fctl plugin is present |
| `kXR_QFinfo` | 9 | ✅ File info |
| `kXR_QFSinfo` | 10 | ✅ Filesystem layout info |
| `kXR_Qopaque` | 16 | ✅ Recognized unstructured FSctl hook; returns the reference-compatible unsupported response when no FSctl plugin is present |
| `kXR_Qopaquf` | 32 | ✅ Recognized path/opaque FSctl hook; validates path and returns the reference-compatible unsupported response without an FSctl plugin |
| `kXR_Qopaqug` | 64 | ✅ Recognized open-handle fctl hook; supports the reference `ofs.tpc cancel` error path and otherwise returns the unsupported fctl response |

---

## Monitoring

| Feature | Status | Notes |
|---|---|---|
| Prometheus metrics (`/metrics`) | ✅ | Per-port native operation counters, native wire/debug counters, WebDAV counters for methods/status/auth/bytes/CORS/fd cache/Range/PROPFIND/HTTP-TPC, and S3 counters for methods/status/auth/bytes/ranges/PUT body modes/ListObjectsV2 diagnostics. See [metrics-and-logging.md](../08-metrics-monitoring/monitoring-guide.md). |
| WLCG Storage Resource Reporting (SRR) | ✅ | HTTP/JSON `storageservice` document (schema v4.x) at an operator-chosen URL via `brix_srr on;`. Live per-share `statvfs` space + endpoints; harvested directly by CRIC / WLCG storage-space accounting. See [`src/protocols/srr/README.md`](../../src/protocols/srr/README.md). |
| XRootD UDP monitoring (f-stream / g-stream) | ❌ (by design) | The binary UDP monitoring/accounting packet stream is intentionally **not** implemented. Storage accounting is served HTTP-native via the SRR endpoint above; transfer/operation counters are on `/metrics` (scrape → MonIT). No `xrootd-monitoring-shoveler` / collector is needed. |

---

## CMS / manager integration

The module can act as a **leaf data server**, a **redirector/manager**, or a
**cache node** that self-registers after each cache fill.

### Leaf data server role (outbound CMS client)

A persistent outbound TCP connection to a configured CMS manager
(`brix_cms_manager`).

| CMS frame | Status | Notes |
|---|---|---|
| `kYR_login` | ✅ | Registers paths, port, space on connect |
| `kYR_ping` / `kYR_pong` | ✅ | Heartbeat round-trip |
| `kYR_avail` | ✅ | Disk free / utilisation reports |
| `kYR_load` | ✅ | Server load info |
| `kYR_space` | ✅ | Space query response |
| `kYR_status` (suspend / resume) | ✅ | Manager-directed drain. Suspend modifier sets `cms_suspended`; new `kXR_login` attempts return `kXR_Overloaded` until a resume frame clears the flag. |
| `kYR_select` / `kYR_try` / `kYR_redirect` | ✅ | Manager-directed client redirect; fully handled by leaf data server to redirect clients |

### Manager/redirector role (inbound CMS server + dynamic redirect)

Enabled by `brix_cms_server on` on the management listener and
`brix_manager_mode on` on the XRootD listener. The server registry is a
128-slot shared-memory table.

| Feature | Status | Notes |
|---|---|---|
| CMS server listener (`brix_cms_server on`) | ✅ | Accepts data server registrations on a dedicated stream listener |
| Dynamic server registry | ✅ | Shared-memory table, spinlock-protected, 128 slots |
| `kXR_locate` → `kXR_redirect` | ✅ | Registry lookup (lowest util); falls back to static `brix_manager_map` |
| `kXR_open` → `kXR_redirect` | ✅ | Registry lookup before local open |
| `kXR_isManager` advertisement | ✅ | Set in `kXR_protocol` response when `brix_manager_mode on` |
| Cache node self-registration | ✅ | `brix_cache` + `brix_manager_mode` together: registers each cached file after fill; unregisters on eviction |
| Sub-manager / hierarchical | ✅ | Run both CMS client and CMS server on one instance; sets `CMS_LOGIN_MODE_MANAGER` in upward login |

See [cluster-mode.md](cluster-management.md) for configuration examples and architecture.

---

## Async I/O

Large memory-backed file reads and writes can use nginx thread pools when nginx
is built with `--with-threads` and a working `brix_thread_pool` is configured.
Covered operations include `kXR_read`, `kXR_readv`, `kXR_pgread`, `kXR_write`,
and `kXR_pgwrite`. Cleartext regular-file reads may instead use file-backed
nginx buffers on the send path, and metadata/open syscalls still run in the
worker. Without thread support the module falls back to synchronous I/O.

---

## WebDAV (`davs://`)

Full WebDAV over HTTPS is implemented as a separate nginx HTTP module.
Operations: OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY (RFC 4918 §9.8 server-side and HTTP-TPC pull/push), MOVE, LOCK, UNLOCK. Authentication accepts proxy certificates and bearer tokens.
Configurable CORS headers are supported for browser-based WebDAV clients.

**Upstream proxy mode** (`brix_webdav_proxy on`): all WebDAV requests — after auth — are forwarded to a backend HTTP or HTTPS server instead of serving from the local filesystem. Supports `http://` and `https://` backends. Three auth bridging policies (`anonymous`, `forward`, `token`). `COPY`/`MOVE` `Destination:` headers are rewritten to the upstream base. Implemented in `src/protocols/webdav/proxy.c`.

See [webdav.md](../04-protocols/webdav-overview.md) for details.

---

## S3-Compatible HTTP

The S3 endpoint is a separate nginx HTTP module for the XrdClS3-style path
subset. It supports path-style `GET`, `HEAD`, `PUT`, `DELETE`, and
`ListObjectsV2` requests under a configured bucket/root.

Authentication is optional AWS Signature Version 4. If
`brix_s3_access_key` is unset, the endpoint accepts anonymous requests.
This path does not use GSI, VOMS, or WLCG bearer-token policy.

Implemented: multipart upload (`CreateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload`, `AbortMultipartUpload`) with staging-directory
lifecycle, part-number validation (1–10 000), atomic assembly via temp-file +
rename, SigV4 presigned URLs, and static-secret `X-Amz-Security-Token`
compatibility via `brix_s3_allow_unsigned_session_token`. Not implemented:
virtual-hosted-style buckets, dynamic STS credential stores, and full AWS S3
policy/IAM semantics.

---

## Known gaps and limitations compared to `xrootd` daemon

All 32 active data-server opcodes in the protocol 5.2 table are implemented.
The one explicitly unsupported opcode (`kXR_gpfile`) has been deprecated since
protocol v3 and has no known live client uses.

The table below covers the gaps that matter for production deployments. Items
are grouped by how severely they block a replacement decision. See
[comparison-with-xrootd.md](../10-reference/design-rationale.md) for deployment-type
analysis.

### Hard blockers — prevent full replacement for specific site types

| Gap | Affected site types | Workaround |
|---|---|---|
| **Full XrdFrm/MSS/tape-driver ecosystem** — FRM queue and Tape REST gateway support exist, but this is not the complete upstream XrdFrm/MSS stack | Sites with tape backends where FTS or physics frameworks depend on exact stage, migrate, purge, space, and recall semantics | Run site-specific prepare/qprep/cancel/evict tests against the real tape backend; keep official XRootD where full MSS behavior is required |

### Soft gaps — reduce feature parity but do not block disk-only POSIX deployments

| Gap | Notes |
|---|---|
| **Native root:// TPC outbound auth polish** — After `kXR_authmore`, the pull client can complete **ztn** (JWT file via `brix_tpc_outbound_bearer_file`) or **GSI** (same PEM as `brix_certificate` / `brix_certificate_key`, with optional server verification via `brix_trusted_ca`). Native TPC source-side `kXR_gotoTLS` and multi-hop delegation beyond this exchange are not implemented. Transparent upstream/proxy connections have their own `kXR_gotoTLS` path; cache/write-through origins keep the separate direct-origin limitations documented in `src/fs/cache/README.md`. |
| **Remote storage backends** — no full PSS, PFC, HDFS, EOS, CASTOR, Ceph, Zip, or upstream OSS-plugin abstraction | By design: module primarily serves confined local POSIX storage; FRM/Tape REST integration is a control-plane bridge, not the full upstream storage plugin ecosystem |
| **Hierarchical CMS gateway/proxy mode** — stream `kYR_select` / `kYR_try` sub-manager redirects are implemented and covered by three-tier tests; a select-then-proxy gateway mode is not implemented | Use standard XRootD client redirects for multi-tier deployments |
| **~~HTTP-TPC OAuth2/OIDC delegation~~ — implemented in `src/protocols/webdav/tpc_cred.c`** | ✅ Implemented — `oidc-agent` UNIX-socket delegation and RFC 8693 token exchange are both supported. Configure with `brix_webdav_tpc_token_endpoint`. See `src/protocols/webdav/tpc_cred.c` and `tests/test_webdav_tpc_cred.py`. |
| **Full XrdAcc / VO authorization database semantics** | Module supports VOMS extraction, `brix_require_vo`, authdb, ACLs, and token-scope checks; it does not reproduce every upstream `XrdAcc` privilege/plugin behavior |
| **Native root:// TPC credential edge cases** | Basic source/destination rendezvous works; TLS-upgraded origins, multihop delegation, and site-specific credential forwarding still need deployment validation |

### Intentionally not implemented

| Feature | Reason |
|---|---|
| `kXR_gpfile` (opcode 3005) | Deprecated since protocol v3; no known live client uses; returns `kXR_Unsupported` |
| `host` / `pwd` authentication | Legacy modes with no modern deployments |
| PSS / full PFC / full XrdFrm storage layers | Remote storage backends are out of scope for a POSIX-backed module; FRM queue/Tape REST support is intentionally narrower than upstream XrdFrm/MSS |
