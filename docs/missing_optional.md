# Missing Optional Features in nginx-xrootd

This document lists optional features present in the official XRootD daemon
(`xrootd`) that are NOT implemented in the nginx-xrootd module. It is organized
by category, with effort estimates and impact assessments to help prioritize
future work.

**Scope**: This covers OPTIONAL features — not hard blockers like tape backends
(PSS, HDFS, EOS, CASTOR), which are out of scope by design for a POSIX-backed
module. For hard blockers, see [status.md](status.md).

**Note**: The nginx-xrootd module already implements all 32 active data-server
opcodes in the protocol 5.2 table, GSI/JWT/SSS authentication, TPC, WebDAV, S3,
Prometheus metrics, CMS/manager integration, and basic caching. See [status.md](status.md)
for the complete implemented feature list.

---

## 1. Erasure Coding (CSI)

| Field | Value |
|---|---|
| **Feature** | XrdOssCsi — Filesystem Checksum (XRDOSS_HASFSCS) |
| **Source location** | `/tmp/xrootd-src/src/XrdOssCsi/` (24 files, ~240 KB) |
| **Description** | Stacked Oss plugin that stores per-page CRC32C values as separate
tag files (`.xrdt`). Write()/Read() calls update/check stored CRC32C values.
pgWrite()/pgRead() directly write/read the values. Supports tagstore, ranges,
page-level encoding/decoding, and nofill/nomissing/noloosewrites options. |
| **nginx-xrootd equivalent** | ❌ No. The module has `kXR_pgwrite`/`kXR_pgread` with
per-page CRC32c in the wire protocol, but no on-disk erasure coding or tagstore. |
| **Estimated effort** | **Very High** — Requires new storage abstraction layer,
tagfile management, page-level I/O coordination, and integration with the
existing pgread/pgwrite paths. Would need a new `src/csi/` directory. |
| **Impact if missing** | **Medium** — Important for sites requiring data
integrity at the storage layer beyond wire protocol CRC. Not needed for
disk-only POSIX deployments. |
| **Dependencies** | nginx thread pool (for async tagfile I/O), shared memory
for tagstore metadata, new config directives. |

---

## 2. Archive Integration (ARC)

| Field | Value |
|---|---|
| **Feature** | XrdOssArc — Tape/Archive integration, backup, compose, stage |
| **Source location** | `/tmp/xrootd-src/src/XrdOssArc/` (24 files, ~200 KB) |
| **Description** | Plugin for integrating tape/archive systems (ARC, CASTOR,
EOS tape). Supports backup, compose (archive creation), stage (restore from
tape), and filesystem monitoring. |
| **nginx-xrootd equivalent** | ❌ No. The module serves local POSIX storage
only. Tape staging is explicitly out of scope (see [status.md](status.md)). |
| **Estimated effort** | **Very High** — Requires integration with external
tape management systems, async staging workflows, and significant new
infrastructure. |
| **Impact if missing** | **Low** — By design, nginx-xrootd serves local POSIX
storage only. Tape backends are not a target use case. |
| **Dependencies** | External tape management APIs (ARC, CASTOR, EOS), async
I/O, significant new code. |

---

## 3. Filer (Frm)

| Field | Value |
|---|---|
| **Feature** | XrdFrm — Distributed file replication, migration, purge, transfer queue |
| **Source location** | `/tmp/xrootd-src/src/XrdFrm/` (38 files, ~490 KB) |
| **Description** | Framework for distributed file replication across sites.
Includes admin interfaces, file management, migration, purge, transfer queue,
and monitoring. Used for multi-site data distribution. |
| **nginx-xrootd equivalent** | ❌ No. The module has CMS-based server
registration and `kXR_locate` redirect, but no automated replication/migration. |
| **Estimated effort** | **Very High** — Requires distributed coordination,
file transfer management, admin interfaces, and significant new infrastructure. |
| **Impact if missing** | **Medium** — Important for multi-site deployments
requiring automated data distribution. Not needed for single-site deployments. |
| **Dependencies** | CMS protocol extension, file transfer subsystem, admin
interfaces. |

---

## 4. Policy File Cache (PFC)

| Field | Value |
|---|---|
| **Feature** | XrdPfc — Caching with allow/blacklist decisions, directory state, snapshots |
| **Source location** | `/tmp/xrootd-src/src/XrdPfc/` (24 files, ~496 KB) |
| **Description** | Policy-based file caching system. Supports allow/blacklist
decisions, directory state tracking, snapshots, purge states, and configurable
policies. Used for intelligent caching with access pattern awareness. |
| **nginx-xrootd equivalent** | ❌ No. The module has basic cache with eviction,
but no policy-based decisions, directory state tracking, or snapshots. |
| **Estimated effort** | **High** — Requires policy engine, directory state
tracking, and integration with the existing cache subsystem. |
| **Impact if missing** | **Low** — Basic cache eviction works for most use
cases. Policy-based caching is a nice-to-have for complex deployments. |
| **Dependencies** | Cache subsystem, policy engine, directory monitoring. |

---

## 5. Parallel Storage Service (PSS)

| Field | Value |
|---|---|
| **Feature** | XrdPss — Parallel I/O, stripe sets, multi-device storage |
| **Source location** | `/tmp/xrootd-src/src/XrdPss/` (16 files, ~184 KB) |
| **Description** | Parallel Storage Service for stripe sets across multiple
devices. Supports parallel I/O, AIO, checksums, and URL-based device
configuration. Used for high-throughput parallel storage. |
| **nginx-xrootd equivalent** | ❌ No. The module serves local POSIX storage
only. PSS is explicitly out of scope (see [status.md](status.md)). |
| **Estimated effort** | **Very High** — Requires parallel I/O infrastructure,
stripe set management, and significant new code. |
| **Impact if missing** | **Low** — By design, nginx-xrootd serves local POSIX
storage only. Parallel storage is not a target use case. |
| **Dependencies** | AIO infrastructure, stripe set management, parallel I/O. |

---

## 6. SciTokens Authentication

| Field | Value |
|---|---|
| **Feature** | XrdSciTokens — Scientific token authentication |
| **Source location** | `/tmp/xrootd-src/src/XrdSciTokens/` (6 files, ~116 KB) |
| **Description** | SciTokens-based authentication. Provides access control
based on SciToken claims, with support for path-based authorization and
group-based access. Includes monitoring and configuration. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module supports JWT/WLCG bearer
tokens (`ztn`) with scope enforcement, but not full SciTokens with path-based
authorization. See `src/token/validate.c` and `src/token/scopes.c`. |
| **Estimated effort** | **Medium** — Requires SciToken-specific scope parsing,
path-based authorization, and integration with the existing token validation
path. |
| **Impact if missing** | **Medium** — Important for sites using SciTokens for
fine-grained path-based authorization. JWT/WLCG tokens cover most use cases
but lack path-specific scopes. |
| **Dependencies** | Token validation infrastructure, scope parsing, path-based
authorization. |

---

## 7. Macaroons Authentication

| Field | Value |
|---|---|
| **Feature** | XrdMacaroons — Macaroon-based authentication and authorization |
| **Source location** | `/tmp/xrootd-src/src/XrdMacaroons/` (10 files, ~96 KB) |
| **Description** | Macaroon-based authentication. Provides third-party
delegation, caveats, and fine-grained authorization. Includes handler,
configure, and authorization modules. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has `src/token/macaroon.c`
with basic macaroon validation, but not full macaroon-based authorization with
caveats and third-party delegation. |
| **Estimated effort** | **Medium** — Requires macaroon caveat parsing,
third-party delegation support, and integration with the existing token
validation path. |
| **Impact if missing** | **Low** — Basic macaroon validation works. Full
macaroon-based authorization is a nice-to-have for complex delegation scenarios. |
| **Dependencies** | Token validation infrastructure, macaroon library, caveat
parsing. |

---

## 8. HTTP Server Module

| Field | Value |
|---|---|
| **Feature** | XrdHttp — HTTP file serving, XRootD over HTTP |
| **Source location** | `/tmp/xrootd-src/src/XrdHttp/` (18 files, ~424 KB) |
| **Description** | HTTP-based XRootD server. Provides HTTP file serving with
checksum support, CORS, monitoring, and extensible handlers. Implements
XRootD protocol over HTTP for firewall-friendly access. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has WebDAV (`davs://`/`https://`)
and S3-compatible HTTP, but not the XrdHttp protocol (XRootD over HTTP).
XrdHttp is a separate protocol that wraps XRootD opcodes in HTTP requests. |
| **Estimated effort** | **High** — Requires new HTTP protocol handler, XRootD
opcode encoding/decoding over HTTP, and integration with the existing HTTP
module infrastructure. |
| **Impact if missing** | **Medium** — Important for firewall-friendly access
where TCP ports are restricted. WebDAV and S3 cover most HTTP use cases but
not XRootD-over-HTTP clients. |
| **Dependencies** | HTTP module infrastructure, XRootD protocol encoding,
CORS support. |

---

## 9. HTTP TPC

| Field | Value |
|---|---|
| **Feature** | XrdHttpTpc — HTTP-based third-party copy |
| **Source location** | `/tmp/xrootd-src/src/XrdHttpTpc/` (16 files, ~176 KB) |
| **Description** | HTTP-based third-party copy. Supports multi-stream transfers,
state management, and PMarkManager for transfer coordination. Used for HTTP-TPC
with advanced features. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has HTTP-TPC in
`src/webdav/tpc.c` with curl-based pull/push, but not the XrdHttpTpc protocol
(HTTP-based TPC with multi-stream and PMarkManager). |
| **Estimated effort** | **High** — Requires HTTP-based TPC protocol handler,
multi-stream transfer coordination, and integration with the existing TPC
infrastructure. |
| **Impact if missing** | **Low** — HTTP-TPC via WebDAV COPY works for most
use cases. XrdHttpTpc is a nice-to-have for advanced HTTP-TPC scenarios. |
| **Dependencies** | HTTP module infrastructure, TPC coordination, multi-stream
transfer support. |

---

## 10. Throttle (Rate Limiting)

| Field | Value |
|---|---|
| **Feature** | XrdThrottle — Rate limiting for file operations |
| **Source location** | `/tmp/xrootd-src/src/XrdThrottle/` (14 files, ~144 KB) |
| **Description** | Rate limiting system for file operations. Supports per-file,
per-filesystem, and per-user throttling with configurable policies. Includes
file-level and filesystem-level throttling. |
| **nginx-xrootd equivalent** | ❌ No. The module has no rate limiting.
Throughput is limited by nginx worker capacity and network bandwidth. |
| **Estimated effort** | **Medium** — Requires rate limiter implementation,
per-connection state tracking, and integration with the existing I/O paths. |
| **Impact if missing** | **Low** — Rate limiting is a nice-to-have for
controlling bandwidth usage. Not critical for most deployments. |
| **Dependencies** | Connection state tracking, rate limiter implementation,
I/O path integration. |

---

## 11. Bandwidth Manager (BWM)

| Field | Value |
|---|---|
| **Feature** | XrdBwm — Bandwidth management with policies and logging |
| **Source location** | `/tmp/xrootd-src/src/XrdBwm/` (14 files, ~156 KB) |
| **Description** | Bandwidth management system. Supports policy-based bandwidth
allocation, per-handle bandwidth tracking, logging, and configurable policies.
Used for QoS and bandwidth guarantees. |
| **nginx-xrootd equivalent** | ❌ No. The module has no bandwidth management.
Throughput is limited by nginx worker capacity and network bandwidth. |
| **Estimated effort** | **High** — Requires bandwidth manager implementation,
policy engine, per-handle tracking, and integration with the existing I/O
paths. |
| **Impact if missing** | **Low** — Bandwidth management is a nice-to-have for
QoS and bandwidth guarantees. Not critical for most deployments. |
| **Dependencies** | I/O path integration, policy engine, per-handle tracking. |

---

## 12. Ceph Integration

| Field | Value |
|---|---|
| **Feature** | XrdCeph — Ceph storage backend |
| **Source location** | `/tmp/xrootd-src/src/XrdCeph/` (18 files, ~196 KB) |
| **Description** | Ceph storage backend plugin. Provides Ceph-specific file
operations, bulk AIO read, buffered file I/O, and XAttr support. Used for
serving data from Ceph storage. |
| **nginx-xrootd equivalent** | ❌ No. The module serves local POSIX storage
only. Ceph is explicitly out of scope (see [status.md](status.md)). |
| **Estimated effort** | **Very High** — Requires Ceph library integration,
RBD/CEPHX authentication, and significant new code. |
| **Impact if missing** | **Low** — By design, nginx-xrootd serves local POSIX
storage only. Ceph storage is not a target use case. |
| **Dependencies** | Ceph library, RBD/CEPX authentication, network I/O. |

---

## 13. ZIP Archive Serving

| Field | Value |
|---|---|
| **Feature** | XrdZip — ZIP file serving |
| **Source location** | `/tmp/xrootd-src/src/XrdZip/` (8 files, ~72 KB) |
| **Description** | ZIP file serving. Provides ZIP archive format support with
CDFH, EOCD, LFH, Extra, ZIP64 support. Used for serving data from ZIP archives
without extraction. |
| **nginx-xrootd equivalent** | ❌ No. The module has no ZIP archive support. |
| **Estimated effort** | **Medium** — Requires ZIP parsing, file extraction from
archives, and integration with the existing read paths. |
| **Impact if missing** | **Low** — ZIP serving is a nice-to-have for serving
data from archives without extraction. Not critical for most deployments. |
| **Dependencies** | ZIP parsing library, file extraction, read path integration. |

---

## 14. Crypto Plugins (Encryption at Rest)

| Field | Value |
|---|---|
| **Feature** | XrdCrypto — Encryption at rest with multiple backends |
| **Source location** | `/tmp/xrootd-src/src/XrdCrypto/` (44 files, ~568 KB) |
| **Description** | Crypto plugin framework for encryption at rest. Supports
multiple backends (OpenSSL, GSI, Lite), cipher operations, RSA, message
digests, and X509 chain validation. Used for encrypting data on disk. |
| **nginx-xrootd equivalent** | ❌ No. The module has no encryption at rest.
Transport encryption (TLS) is supported, but not data-at-rest encryption. |
| **Estimated effort** | **High** — Requires crypto plugin framework, encryption
integration with file I/O paths, and key management. |
| **Impact if missing** | **Medium** — Important for sites requiring data-at-rest
encryption. Transport encryption (TLS) covers data-in-transit. |
| **Dependencies** | Crypto library, key management, file I/O path integration. |

---

## 15. Audit Logging

| Field | Value |
|---|---|
| **Feature** | XrdFrmAdminAudit — Audit trail for file operations |
| **Source location** | `/tmp/xrootd-src/src/XrdFrm/XrdFrmAdminAudit.cc` (24 KB) |
| **Description** | Audit trail for file operations. Provides detailed logging
of file access, modifications, and administrative actions. Used for compliance
and security auditing. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has access logging
(`xrootd_access_log`) with per-operation details, but not a dedicated audit
trail with administrative action tracking. |
| **Estimated effort** | **Low** — Requires audit-specific log format and
integration with the existing access logging path. |
| **Impact if missing** | **Low** — Access logging covers most audit needs.
Dedicated audit trail is a nice-to-have for compliance requirements. |
| **Dependencies** | Access logging infrastructure, audit log format. |

---

## 16. Trace/Debugging

| Field | Value |
|---|---|
| **Feature** | XrdOssTrace — Detailed tracing for debugging |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssTrace.hh` (3 KB) |
| **Description** | Detailed tracing framework for debugging. Provides trace
points for file operations, I/O, and system events. Used for development and
troubleshooting. |
| **nginx-xrootd equivalent** | ❌ No. The module has no dedicated tracing
framework. Debugging relies on nginx error logs and access logs. |
| **Estimated effort** | **Low** — Requires trace point definitions and
integration with the existing logging infrastructure. |
| **Impact if missing** | **Low** — Debugging relies on nginx error logs and
access logs. Tracing is a development tool, not a production feature. |
| **Dependencies** | Logging infrastructure, trace point definitions. |

---

## 17. OSS Stats Module

| Field | Value |
|---|---|
| **Feature** | XrdOssStats — Detailed statistics for file operations |
| **Source location** | `/tmp/xrootd-src/src/XrdOssStats/` (10 files, ~76 KB) |
| **Description** | Detailed statistics for file operations. Provides per-file,
per-directory, and per-filesystem statistics with configurable collection and
export. Used for monitoring and capacity planning. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has Prometheus metrics
with per-operation counters, but not the detailed per-file/per-directory
statistics from XrdOssStats. |
| **Estimated effort** | **Medium** — Requires statistics collection framework,
per-file/per-directory tracking, and integration with the existing metrics
infrastructure. |
| **Impact if missing** | **Low** — Prometheus metrics cover most monitoring
needs. Per-file/per-directory statistics are a nice-to-have for detailed
capacity planning. |
| **Dependencies** | Metrics infrastructure, per-file tracking, statistics
collection framework. |

---

## 18. Archive Transfer (At)

| Field | Value |
|---|---|
| **Feature** | XrdOssAt — Archive transfer |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssAt.cc` (8 KB) |
| **Description** | Archive transfer support. Provides archive file transfer
capabilities with integration to archive systems. Used for moving data to/from
archive storage. |
| **nginx-xrootd equivalent** | ❌ No. The module serves local POSIX storage
only. Archive transfer is explicitly out of scope (see [status.md](status.md)). |
| **Estimated effort** | **High** — Requires archive transfer protocol support,
integration with archive systems, and new infrastructure. |
| **Impact if missing** | **Low** — By design, nginx-xrootd serves local POSIX
storage only. Archive transfer is not a target use case. |
| **Dependencies** | Archive system integration, transfer protocol support. |

---

## 19. Relocation (Reloc)

| Field | Value |
|---|---|
| **Feature** | XrdOssReloc — File relocation |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssReloc.cc` (8 KB) |
| **Description** | File relocation support. Provides file relocation capabilities
with integration to storage management systems. Used for moving files between
storage tiers or locations. |
| **nginx-xrootd equivalent** | ❌ No. The module has `kXR_mv` for file
renaming within the same filesystem, but not cross-filesystem relocation. |
| **Estimated effort** | **Medium** — Requires cross-filesystem file transfer,
relocation protocol support, and integration with storage management systems. |
| **Impact if missing** | **Low** — Cross-filesystem relocation is a nice-to-have
for storage tier migration. Not critical for most deployments. |
| **Dependencies** | Cross-filesystem transfer, relocation protocol, storage
management integration. |

---

## 20. Space Management

| Field | Value |
|---|---|
| **Feature** | XrdOssSpace — Advanced space management |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssSpace.cc` (19 KB) |
| **Description** | Advanced space management. Provides space allocation, quota
management, and space reporting with integration to storage management systems.
Used for managing storage space across multiple volumes. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has `kXR_query` Qspace
with `statvfs` for filesystem free/total, but not advanced space management
with quota and volume management. |
| **Estimated effort** | **Medium** — Requires space management framework,
quota enforcement, and integration with the existing query infrastructure. |
| **Impact if missing** | **Low** — Basic space reporting works. Advanced space
management is a nice-to-have for complex storage deployments. |
| **Dependencies** | Space management framework, quota enforcement, query
infrastructure. |

---

## 21. Memory I/O (Mio)

| Field | Value |
|---|---|
| **Feature** | XrdOssMio — Memory-backed I/O |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssMio.cc` (12 KB) |
| **Description** | Memory-backed I/O. Provides memory-backed file operations
with support for mmap-like access patterns. Used for high-performance I/O with
memory-backed buffers. |
| **nginx-xrootd equivalent** | ❌ No. The module has memory-backed reads for
TLS paths, but not full memory-backed I/O with mmap-like access patterns. |
| **Estimated effort** | **Medium** — Requires memory-backed I/O framework,
mmap support, and integration with the existing I/O paths. |
| **Impact if missing** | **Low** — Memory-backed reads work for TLS paths.
Full memory-backed I/O is a nice-to-have for high-performance scenarios. |
| **Dependencies** | I/O path integration, mmap support, memory management. |

---

## 22. Mass Storage System (MSS)

| Field | Value |
|---|---|
| **Feature** | XrdOssMSS — Mass storage system integration |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssMSS.cc` (16 KB) |
| **Description** | Mass storage system integration. Provides integration with
mass storage systems (tape, library) for data access and management. Used for
serving data from mass storage systems. |
| **nginx-xrootd equivalent** | ❌ No. The module serves local POSIX storage
only. Mass storage integration is explicitly out of scope (see [status.md](status.md)). |
| **Estimated effort** | **Very High** — Requires mass storage system integration,
tape management, and significant new infrastructure. |
| **Impact if missing** | **Low** — By design, nginx-xrootd serves local POSIX
storage only. Mass storage is not a target use case. |
| **Dependencies** | Mass storage system APIs, tape management, integration
infrastructure. |

---

## 23. Cache Configuration

| Field | Value |
|---|---|
| **Feature** | XrdOssCache — Advanced caching configuration |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssCache.cc` (31 KB) |
| **Description** | Advanced caching configuration. Provides cache size management,
eviction policies, and cache monitoring with integration to storage management
systems. Used for managing cache behavior across multiple volumes. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has basic cache with
eviction threshold, but not advanced cache configuration with multiple eviction
policies and cache monitoring. |
| **Estimated effort** | **Medium** — Requires advanced cache configuration
framework, multiple eviction policies, and integration with the existing cache
infrastructure. |
| **Impact if missing** | **Low** — Basic cache eviction works for most use
cases. Advanced cache configuration is a nice-to-have for complex deployments. |
| **Dependencies** | Cache infrastructure, eviction policy framework, cache
monitoring. |

---

## 24. Server-Side Copy

| Field | Value |
|---|---|
| **Feature** | XrdOssCopy — Server-side copy |
| **Source location** | `/tmp/xrootd-src/src/XrdOss/XrdOssCopy.cc` (7 KB) |
| **Description** | Server-side copy. Provides efficient file copy operations
with support for cross-directory and cross-volume copies. Used for fast file
duplication. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has `kXR_clone` for
server-side range copy with `copy_file_range(2)`, but not the full XrdOssCopy
with cross-directory and cross-volume support. |
| **Estimated effort** | **Low** — Requires cross-directory/cross-volume copy
support and integration with the existing clone infrastructure. |
| **Impact if missing** | **Low** — `kXR_clone` works for same-filesystem copies.
Cross-directory/cross-volume copy is a nice-to-have. |
| **Dependencies** | Clone infrastructure, cross-volume copy support. |

---

## 25. Operation Stats

| Field | Value |
|---|---|
| **Feature** | XrdOfsStats — Detailed operation statistics |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsStats.cc` (3 KB) |
| **Description** | Detailed operation statistics. Provides per-operation timing,
byte counts, and error rates with integration to monitoring systems. Used for
performance analysis and troubleshooting. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has Prometheus metrics
with per-operation counters and access logs with timing, but not the detailed
per-operation statistics from XrdOfsStats. |
| **Estimated effort** | **Low** — Requires operation statistics collection
and integration with the existing metrics infrastructure. |
| **Impact if missing** | **Low** — Prometheus metrics and access logs cover
most monitoring needs. Detailed operation statistics are a nice-to-have for
performance analysis. |
| **Dependencies** | Metrics infrastructure, operation timing collection. |

---

## 26. Event Recording (EVR)

| Field | Value |
|---|---|
| **Feature** | XrdOfsEvr — Event recording |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsEvr.cc` (12 KB) |
| **Description** | Event recording. Provides event recording for file operations
with support for event replay and analysis. Used for debugging and audit. |
| **nginx-xrootd equivalent** | ❌ No. The module has no event recording
framework. |
| **Estimated effort** | **Medium** — Requires event recording framework, event
storage, and integration with the existing logging infrastructure. |
| **Impact if missing** | **Low** — Event recording is a development/debugging
tool, not a production feature. |
| **Dependencies** | Logging infrastructure, event storage, event replay. |

---

## 27. Event Streaming (EVS)

| Field | Value |
|---|---|
| **Feature** | XrdOfsEvs — Event streaming |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsEvs.cc` (19 KB) |
| **Description** | Event streaming. Provides event streaming for file operations
with support for real-time event monitoring and analysis. Used for real-time
monitoring and alerting. |
| **nginx-xrootd equivalent** | ❌ No. The module has no event streaming
framework. |
| **Estimated effort** | **Medium** — Requires event streaming framework, real-
time event processing, and integration with the existing metrics infrastructure. |
| **Impact if missing** | **Low** — Event streaming is a monitoring/alerting
tool, not a production feature. Prometheus metrics cover most monitoring needs. |
| **Dependencies** | Metrics infrastructure, real-time event processing, event
streaming framework. |

---

## 28. Post-Op Completion Queue (PosCQ)

| Field | Value |
|---|---|
| **Feature** | XrdOfsPoscq — Post-operation completion queue |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsPoscq.cc` (13 KB) |
| **Description** | Post-operation completion queue. Provides async completion
queue for file operations with support for callback registration and completion
notification. Used for async I/O and event-driven processing. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has nginx thread pool
for async I/O, but not the full async completion queue with callback registration. |
| **Estimated effort** | **Medium** — Requires async completion queue
implementation, callback registration, and integration with the existing
thread pool infrastructure. |
| **Impact if missing** | **Low** — nginx thread pool covers async I/O needs.
Full async completion queue is a nice-to-have for complex async scenarios. |
| **Dependencies** | Thread pool infrastructure, callback framework, async
completion queue implementation. |

---

## 29. Prepare/GPI

| Field | Value |
|---|---|
| **Feature** | XrdOfsPrepGPI — Prepare with GPI |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsPrepGPI.cc` (30 KB) |
| **Description** | Prepare with GPI (Global Prepare Interface). Provides prepare
with GPI support for distributed transaction coordination. Used for ensuring
consistency across distributed storage systems. |
| **nginx-xrootd equivalent** | ❌ No. The module has `kXR_prepare` with path
validation and existence check, but not GPI-based distributed transaction
coordination. |
| **Estimated effort** | **High** — Requires GPI protocol support, distributed
transaction coordination, and significant new infrastructure. |
| **Impact if missing** | **Low** — `kXR_prepare` works for path validation.
GPI-based distributed transactions are a nice-to-have for complex distributed
scenarios. |
| **Dependencies** | GPI protocol, distributed transaction coordination, network
I/O. |

---

## 30. FSctl/FSinfo Plugins

| Field | Value |
|---|---|
| **Feature** | XrdOfsFSctl — FSctl/FSinfo plugin hooks |
| **Source location** | `/tmp/xrootd-src/src/XrdOfs/XrdOfsFSctl.cc` |
| **Description** | FSctl/FSinfo plugin hooks. Provides plugin hooks for custom
FSctl and FSinfo operations. Used for extending XRootD with custom file system
operations. |
| **nginx-xrootd equivalent** | ⚠️ Partial. The module has Qvisa/Qopaque/Qopaquf/
Qopaqug hooks that return reference-compatible unsupported responses, but not
full plugin hooks for custom FSctl/FSinfo operations. |
| **Estimated effort** | **Medium** — Requires plugin framework, FSctl/FSinfo
handler registration, and integration with the existing query infrastructure. |
| **Impact if missing** | **Low** — Query hooks work for standard operations.
Custom FSctl/FSinfo plugins are a nice-to-have for custom extensions. |
| **Dependencies** | Plugin framework, query infrastructure, handler registration. |

---

## Summary and Prioritization

### High Impact (consider for roadmap)

| Feature | Effort | Impact | Notes |
|---|---|---|---|
| **SciTokens** | Medium | Medium | Important for sites using SciTokens for fine-grained path-based authorization |
| **HTTP Server Module** | High | Medium | Important for firewall-friendly access where TCP ports are restricted |
| **Crypto Plugins** | High | Medium | Important for sites requiring data-at-rest encryption |
| **Erasure Coding (CSI)** | Very High | Medium | Important for data integrity at storage layer |

### Medium Impact (nice-to-have)

| Feature | Effort | Impact | Notes |
|---|---|---|---|
| **Macaroons** | Medium | Low | Basic macaroon validation works; full authorization is nice-to-have |
| **HTTP TPC** | High | Low | HTTP-TPC via WebDAV COPY works for most use cases |
| **Space Management** | Medium | Low | Basic space reporting works; advanced management is nice-to-have |
| **OSS Stats** | Medium | Low | Prometheus metrics cover most monitoring needs |
| **Server-Side Copy** | Low | Low | `kXR_clone` works for same-filesystem copies |
| **Operation Stats** | Low | Low | Prometheus metrics and access logs cover most monitoring needs |

### Low Impact (not prioritized)

| Feature | Effort | Impact | Notes |
|---|---|---|---|
| **Throttle** | Medium | Low | Rate limiting is a nice-to-have for controlling bandwidth |
| **BWM** | High | Low | Bandwidth management is a nice-to-have for QoS |
| **PFC** | High | Low | Basic cache eviction works for most use cases |
| **Audit Logging** | Low | Low | Access logging covers most audit needs |
| **Trace/Debugging** | Low | Low | Development tool, not a production feature |
| **ZIP Archive** | Medium | Low | Nice-to-have for serving data from archives |
| **Mio** | Medium | Low | Memory-backed reads work for TLS paths |
| **PosCQ** | Medium | Low | nginx thread pool covers async I/O needs |
| **Prepare/GPI** | High | Low | `kXR_prepare` works for path validation |
| **FSctl/FSinfo** | Medium | Low | Query hooks work for standard operations |
| **EVR** | Medium | Low | Development/debugging tool |
| **EVS** | Medium | Low | Monitoring/alerting tool |
| **Cache Config** | Medium | Low | Basic cache eviction works for most use cases |

### Out of Scope (not planned)

| Feature | Reason |
|---|---|
| **Archive Integration (ARC)** | Tape/archive integration is out of scope for POSIX-backed module |
| **Filer (Frm)** | Distributed file replication is out of scope |
| **PSS** | Parallel storage is out of scope for POSIX-backed module |
| **Ceph Integration** | Ceph storage is out of scope for POSIX-backed module |
| **Archive Transfer (At)** | Archive transfer is out of scope for POSIX-backed module |
| **Mass Storage (MSS)** | Mass storage integration is out of scope for POSIX-backed module |
| **Relocation** | Cross-filesystem relocation is out of scope |

---

## References

- [status.md](status.md) — Full implementation status with opcode coverage, authentication, TLS, query subtypes, monitoring, CMS/manager integration, WebDAV, S3, and known gaps
- [comparison-with-xrootd.md](comparison-with-xrootd.md) — Deployment-type analysis and design rationale
- [cluster-mode.md](cluster-mode.md) — Manager mode configuration and architecture
- [webdav.md](webdav.md) — WebDAV configuration and features
- [metrics-and-logging.md](metrics-and-logging.md) — Prometheus metrics and access logging
