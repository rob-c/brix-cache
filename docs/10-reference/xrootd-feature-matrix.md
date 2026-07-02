# XRootD Feature Matrix

Last verified: 2026-06-14

This is the current high-level matrix for gnuBall versus the official
XRootD source tree under `/tmp/xrootd-src`. It intentionally excludes the
official UDP stream monitoring stack: this project has rejected that subsystem
and uses Prometheus/SRR/dashboard/access-log reporting instead.

For file-by-file evidence, reviewer cautions, and the exact upstream source
paths checked, see
[Source-Verified XRootD Comparison](source-verified-xrootd-comparison.md).

## Legend

| Mark | Meaning |
|---|---|
| Yes | Implemented in source and documented as current behavior |
| Partial | Implemented for the common path, but missing upstream breadth or site-specific integrations |
| No | Not implemented |
| N/A | Intentionally not applicable to that implementation |
| nginx+ | Implemented here and not present as an equivalent upstream XRootD server feature |

## Native XRootD Protocol

| Feature | Official XRootD | gnuBall | Reviewer notes |
|---|---:|---:|---|
| Protocol 5.2 framing and login lifecycle | Yes | Yes | gnuBall implements the stream lifecycle in `src/protocols/root/handshake`, `src/protocols/root/session`, and `src/protocols/root/protocol`. |
| Active request opcodes | Yes | Yes | All active wire opcodes reviewed are implemented or intentionally return the same class of unsupported response where upstream defaults do. |
| Legacy `kXR_gpfile` | No/default unsupported | No/default unsupported | Upstream default path returns `kXR_Unsupported`; this is not a practical parity blocker. |
| Vector, page, and signed reads | Yes | Yes | Includes readv, pgread CRC32c framing, and signature verification paths. |
| Writes, page writes, sync, truncate | Yes | Yes | Includes pgwrite CRC32c validation and sync paths. |
| Directory and namespace mutations | Yes | Yes | Includes dirlist, mkdir, rmdir, rm, mv, chmod, truncate, and fattr coverage. |
| Locate, query, prepare, evict | Yes | Partial | Core query/locate coverage exists. gnuBall has FRM/Tape REST gateway support, but not the full upstream XrdFrm/MSS ecosystem. |
| Bind/session recovery | Yes | Yes | Implemented in `src/protocols/root/session/bind.c` and registry helpers. |
| Async attention packets | Yes | Partial | Operational paths exist around queue/wait behavior, but broad upstream attention semantics should be reviewed for each deployment mode. |
| Protocol flags | Yes | Yes | Current flag set includes async, sendfile, attrMeta, attrVirtRdr, attrSuper, recoverWrites, collapseRedirect, and TLS advertisement. |
| GPF/extended collection flags | Yes | No | Not advertised by gnuBall; leaving this unimplemented is intentional unless a site depends on those upstream behaviors. |

## Authentication and Authorization

| Feature | Official XRootD | gnuBall | Reviewer notes |
|---|---:|---:|---|
| Anonymous auth | Yes | Yes | Supported for native stream and HTTP/WebDAV surfaces where enabled. |
| GSI/X.509 | Yes | Yes | Native stream and WebDAV support are present. |
| Token auth / WLCG bearer tokens | Yes | Yes | Includes native and HTTP/WebDAV handling. |
| SSS shared-secret auth | Yes | Yes | Implemented in `src/auth/sss`. |
| UNIX credential auth | Yes | Yes | Implemented in `src/unixauth`. |
| Kerberos 5 auth | Yes | Yes | Optional build-time support in `src/auth/krb5`; older docs that call this missing are stale. |
| Macaroons | Yes | Yes | Includes token mint/verify and WebDAV delegation flows. |
| VOMS and ACL policy | Yes | Yes | Implemented through policy, ACL, authdb, and VOMS helpers. |
| `host` and `pwd` auth protocols | Yes | Yes | Implemented in `src/auth/host/` (reverse-DNS allowlist) and `src/auth/pwd/` (DH-bootstrapped password handshake); wire-equivalents, not the `xrdpwdadmin` admin ecosystem. |
| Full upstream `XrdAcc` semantics | Yes | Partial | gnuBall has ACL/authdb/VOMS/scope checks but not every upstream `XrdAcc` privilege model and plugin behavior. |
| External security plugin ecosystem | Yes | Partial | gnuBall implements selected native mechanisms directly rather than loading the full upstream sec plugin matrix. |

## HTTP, WebDAV, and Transfer Protocols

| Feature | Official XRootD | gnuBall | Reviewer notes |
|---|---:|---:|---|
| XrdHttp basic GET/PUT/HEAD/DELETE | Yes | Yes | Both projects implement HTTP data access surfaces. |
| WebDAV namespace methods | Yes | Yes | gnuBall implements GET, PUT, DELETE, MOVE, COPY, MKCOL, PROPFIND, OPTIONS, LOCK/UNLOCK, and related helpers. |
| HTTP third-party-copy | Yes | Yes | Upstream has `XrdHttpTpc`; gnuBall has WebDAV TPC with hardened curl/libcurl helper paths. Old claims that upstream lacks HTTP-TPC are wrong. |
| HTTP-TPC performance markers/chunked progress | Yes | Yes | gnuBall docs and source include marker/progress handling. |
| HTTP-TPC multistream/range transfer | Yes | Yes | gnuBall implements multi-stream/range transfer paths; integration differs from upstream. |
| OAuth2/OIDC credential delegation | Yes | Yes | gnuBall includes delegation/token-exchange helpers; older docs saying this is rejected are stale. |
| Native root TPC | Yes | Partial | Source/destination rendezvous exists. Site review is still needed for TLS-upgraded origins, multihop delegation, and non-default credential paths. |
| XrdCl client library | Yes | No | gnuBall is a server module and does not attempt to replace the upstream client library. |
| S3 REST server | No | nginx+ | Implemented under `src/protocols/s3` with SigV4/anonymous auth modes. |
| WLCG Tape REST gateway | No equivalent | nginx+ | Implemented as a gateway/control-plane surface; it is not a full replacement for upstream XrdFrm/MSS. |

## Storage and Backend Ecosystem

| Feature | Official XRootD | gnuBall | Reviewer notes |
|---|---:|---:|---|
| POSIX filesystem backend | Yes | Yes | Primary supported data plane in gnuBall. |
| Confined canonical path handling | Plugin/config dependent | Yes | gnuBall centralizes canonical confinement helpers and treats them as invariants. |
| Open-file cache and sendfile-style reads | Yes | Yes | Implemented with nginx-aware sendfile/TLS buffer separation. |
| Full PSS proxy storage | Yes | No | Not implemented; upstream remains stronger for PSS/PFC deployments. |
| Full proxy file cache (PFC) | Yes | Partial/No | gnuBall has open/cache and local data-plane helpers, not the full upstream PFC subsystem. |
| Ceph/Rados, CSI, OssArc, HDFS-style OSS plugins | Yes | No | Not implemented as upstream-compatible plugin stacks (these are the remaining hard backend gaps). |
| ZIP-member access (`XrdZip`) | Yes | Partial | ZIP-member serving over HTTP implemented in `src/protocols/root/zip/`; not full upstream cross-protocol parity. |
| Checksum plugin ecosystem | Yes | Partial | gnuBall supports checksum query paths plus CRC-64/XZ and CRC-64/NVME, but not the full upstream checksum plugin matrix. |
| XrdFrm/MSS/tape staging ecosystem | Yes | Partial | gnuBall has FRM queue/Tape REST integration; full upstream migration, purge, space, and MSS driver behavior needs site review. |

## Operations, Observability, and Policy

| Feature | Official XRootD | gnuBall | Reviewer notes |
|---|---:|---:|---|
| UDP XrdMon monitoring | Yes | N/A | Explicitly refused for this project. Do not count this as a missing target. |
| Prometheus metrics endpoint | Limited/eos-site dependent | nginx+ | Implemented as a first-class `/metrics` surface. |
| Storage Resource Reporting (SRR) | Limited/eos-site dependent | nginx+ | Implemented in project docs and source. |
| Built-in operations dashboard | No equivalent | nginx+ | Implemented under dashboard/ops docs and module surfaces. |
| Per-identity rate, bandwidth, and concurrency limits | Plugin/config dependent | nginx+ | Implemented through shared-memory policy helpers. |
| Dynamic upstream health/management | Plugin/config dependent | nginx+ | Implemented for this module's nginx deployment model; not a drop-in CMS replacement. |
| Traffic mirroring/shadow replay | No equivalent | nginx+ | HTTP/WebDAV and stream mirror support exists, including opt-in write/data-write mirroring gated by `xrootd_mirror_writes`. |

## Current Review Hotspots

| Area | Status | Why reviewers should care |
|---|---|---|
| Full XrdFrm/MSS parity | Partial | Sites with tape-backed data services must validate prepare/evict/cancel semantics against their real tape workflow. |
| `host`/`pwd` auth | Implemented | `src/auth/host/` + `src/auth/pwd/`; closed gap. Wire-equivalents, not the `xrdpwdadmin` admin ecosystem. |
| Full `XrdAcc` and *custom* security plugin ecosystem | Partial | gnuBall implements practical ACL/token/VOMS controls and all standard auth schemes, but not arbitrary loadable third-party sec plugins. |
| PSS/PFC/Ceph/OssCsi/OssArc backends | Missing/partial | Upstream XRootD remains the better fit for deployments built around those backend plugins (ZIP-member access is implemented). |
| Native TPC credential edge cases | Partial | Source/destination TPC works, but TLS-upgraded origins and multihop delegation need deployment-specific verification. |
| CRC64 and checksum plugin breadth | Partial | CRC64/CRC64NVME are implemented; the upstream checksum plugin catalog is still broader. |
| CMS manager/admin feature breadth | Partial | gnuBall has manager/upstream controls, but not every upstream CMS admin command or redirection mode. |

## Claims Removed From Older Versions

These statements appeared in older docs and are no longer accurate:

| Old claim | Current source-verified status |
|---|---|
| "Kerberos is not implemented." | Kerberos 5 support exists behind optional build-time support in `src/auth/krb5`. |
| "Official XRootD does not have HTTP-TPC." | Upstream has `src/XrdHttpTpc`; this project should not claim exclusivity for HTTP-TPC. |
| "gnuBall lacks HTTP-TPC multistream/performance markers." | Current WebDAV TPC paths implement multistream/range transfer and progress/marker behavior. |
| "Prepare always returns request id 0." | That is only the FRM-off legacy behavior; FRM-enabled operation returns durable request ids. |
| "Write mirroring is out of scope." | Current source has opt-in HTTP/WebDAV write mirroring and stream data-write replay gated by `xrootd_mirror_writes`. |
| "S3 auth is planned." | S3 SigV4/anonymous auth is implemented under `src/protocols/s3`. |
