# XRootD Feature Matrix

Last verified: 2026-06-14

> **Status (2026-09-09 — 2.0).** Not re-verified since 2026-06-14. For what 2.0 ships,
> what it deliberately does not, and what is still open, use the 2.0 register,
> [`release-2.0-readiness.md`](release-2.0-readiness.md) — its parity rows supersede any
> ⚠️/❌ below. Axis (e) of that register closed **F1–F20** (the thirteen accepted-only
> `brix_frm_*` knobs and the durable stage journal, `stagemsg`/StageEvents, the OssArc
> dataset seal, the per-space purge-policy grammar with an external policy program,
> `pfc.urlcgi` + PSS forwarding, the RAM-tier metric rows, native `root://` TPC
> **multihop** delegation and multi-stream *pull*, the site checksum plugin loader, the
> sss v2 endorsement/proxied-credential wave, the health-check family,
> `brix_mirror_exclude_opcodes` read/readv, the four metric wishlist categories, native
> `root://` TPC **push** with multi-stream on it, the `cms.fsxeq` operator program for
> forwarded namespace ops, and the `ofs.tpc` identity matrix layered inside the
> host-plane TPC confinement, and the `xrd.tlsca` CRL-scope and verification-log
> residuals — whose lab also found and fixed **F22**, a CRL a worker could not read
> silently disarming revocation — and the native authdb residual grammar: the compound
> `u g p a v l` selector set, positional VOMS vorg+role pairing, and the `x` stage
> privilege) and, with **F21** — full per-user POSIX identity across the VFS seam, whose audit
> found the posix plane already impersonating at the `beneath`/`confined_canon` seam
> and closed the one un-brokered verb, `RENAME_EXCHANGE` — landed on 2026-09-10,
> leaves nothing open: axis (e) is closed in full at F1–F22. A row below that names a closed item is stale by construction; this file is
> kept as a historical snapshot and is no longer maintained row by row.

This is the current high-level matrix for BriX-Cache versus the official
XRootD project. It intentionally excludes the
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

| Feature | Official XRootD | BriX-Cache | Reviewer notes |
|---|---:|---:|---|
| Protocol 5.2 framing and login lifecycle | Yes | Yes | BriX-Cache implements the stream lifecycle in `src/protocols/root/handshake`, `src/protocols/root/session`, and `src/protocols/root/protocol`. |
| Active request opcodes | Yes | Yes | All active wire opcodes reviewed are implemented or intentionally return the same class of unsupported response where upstream defaults do. |
| Legacy `kXR_gpfile` | No/default unsupported | No/default unsupported | Upstream default path returns `kXR_Unsupported`; this is not a practical parity blocker. |
| Vector, page, and signed reads | Yes | Yes | Includes readv, pgread CRC32c framing, and signature verification paths. |
| Writes, page writes, sync, truncate | Yes | Yes | Includes pgwrite CRC32c validation and sync paths. |
| Directory and namespace mutations | Yes | Yes | Includes dirlist, mkdir, rmdir, rm, mv, chmod, truncate, and fattr coverage. |
| Locate, query, prepare, evict | Yes | Partial | Core query/locate coverage exists. BriX-Cache has FRM/Tape REST gateway support, but not the full upstream XrdFrm/MSS ecosystem. |
| Bind/session recovery | Yes | Yes | Implemented in `src/protocols/root/session/bind.c` and registry helpers. |
| Async attention packets | Yes | Partial | Operational paths exist around queue/wait behavior, but broad upstream attention semantics should be reviewed for each deployment mode. |
| Protocol flags | Yes | Yes | Current flag set includes async, sendfile, attrMeta, attrVirtRdr, attrSuper, recoverWrites, collapseRedirect, and TLS advertisement. |
| GPF/extended collection flags | Yes | No | Not advertised by BriX-Cache; leaving this unimplemented is intentional unless a site depends on those upstream behaviors. |

## Authentication and Authorization

| Feature | Official XRootD | BriX-Cache | Reviewer notes |
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
| Full upstream `XrdAcc` semantics | Yes | Partial | BriX-Cache has ACL/authdb/VOMS/scope checks but not every upstream `XrdAcc` privilege model and plugin behavior. |
| External security plugin ecosystem | Yes | Partial | BriX-Cache implements selected native mechanisms directly rather than loading the full upstream sec plugin matrix. |

## HTTP, WebDAV, and Transfer Protocols

| Feature | Official XRootD | BriX-Cache | Reviewer notes |
|---|---:|---:|---|
| XrdHttp basic GET/PUT/HEAD/DELETE | Yes | Yes | Both projects implement HTTP data access surfaces. |
| WebDAV namespace methods | Yes | Yes | BriX-Cache implements GET, PUT, DELETE, MOVE, COPY, MKCOL, PROPFIND, OPTIONS, LOCK/UNLOCK, and related helpers. |
| HTTP third-party-copy | Yes | Yes | Upstream has `XrdHttpTpc`; BriX-Cache has WebDAV TPC with hardened curl/libcurl helper paths. Old claims that upstream lacks HTTP-TPC are wrong. |
| HTTP-TPC performance markers/chunked progress | Yes | Yes | BriX-Cache docs and source include marker/progress handling. |
| HTTP-TPC multistream/range transfer | Yes | Yes | BriX-Cache implements multi-stream/range transfer paths; integration differs from upstream. |
| OAuth2/OIDC credential delegation | Yes | Yes | BriX-Cache includes delegation/token-exchange helpers; older docs saying this is rejected are stale. |
| Native root TPC | Yes | Yes | Source/destination rendezvous, TLS-upgraded origins, redirect following (`brix_tpc_max_hops`) and multi-stream pulls (`brix_tpc_streams`). Site review is still needed for non-default credential paths. |
| XrdCl client library | Yes | Yes (clean-room) | `client/` is a full native client stack — libbrix (sync + epoll/io_uring async cores), GSI/sss/pwd/krb5/token auth with client-side GSI delegation, pgread/pgwrite with pgRetry, readv/writev, metalink, extreme copy (`--sources`), TPC orchestration, xrdcp/xrdfs CLIs, FUSE mount, LD_PRELOAD shim. It is a clean-room implementation, not a port of libXrdCl (no XrdCl API/ABI compatibility). See the 2026-08-04 feature-parity audit §7 for the residual gap list. |
| S3 REST server | No | nginx+ | Implemented under `src/protocols/s3` with SigV4/anonymous auth modes. |
| WLCG Tape REST gateway | No equivalent | nginx+ | Implemented as a gateway/control-plane surface; it is not a full replacement for upstream XrdFrm/MSS. |

## Storage and Backend Ecosystem

| Feature | Official XRootD | BriX-Cache | Reviewer notes |
|---|---:|---:|---|
| POSIX filesystem backend | Yes | Yes | Primary supported data plane in BriX-Cache. |
| Confined canonical path handling | Plugin/config dependent | Yes | BriX-Cache centralizes canonical confinement helpers and treats them as invariants. |
| Open-file cache and sendfile-style reads | Yes | Yes | Implemented with nginx-aware sendfile/TLS buffer separation. |
| Full PSS proxy storage | Yes | Partial | 2.0 F5 added the XrdPss convention where the client names the origin inside the path: `brix_storage_backend forward://root[,roots] permit=<host\|.suffix>…` opens one child per admitted origin and refuses a host outside the permit list before it dials. Not the full PSS plugin stack — no loadable `pss` plugins and no `pss.*` config namespace. |
| Full proxy file cache (PFC) | Yes | Partial | Open/cache and local data-plane helpers, plus the `pfc.urlcgi` analog `brix_cache_urlcgi` (2.0 F5): a client's per-open `pfc.blocksize=` / `pfc.prefetch=` hints, each clamped into operator-set bounds and ignored when unarmed. Still not the full upstream PFC subsystem — no PFC policy engine and no cinfo file-state database. |
| Ceph/Rados, CSI, OssArc, HDFS-style OSS plugins | Yes | Partial | Not a loadable OSS plugin *host* — backends are compiled-in drivers under `src/fs/backend/`. In-tree since this row was written: the striper-interop Ceph/RADOS driver (`rados/sd_ceph*`, plus read-only `cephfsro`), the CSI page tagstore (`csi_tagstore.c`), and the OssArc dataset seal (2.0 F3). Erasure coding and the object-archive backend remain the hard gaps. |
| ZIP-member access (`XrdZip`) | Yes | Partial | ZIP-member serving over HTTP implemented in `src/protocols/root/zip/`; not full upstream cross-protocol parity. |
| Checksum plugin ecosystem | Yes | Yes | 2.0 ships ten built-ins (adler32, crc32, crc32c, crc64, crc64nvme, zcrc32, md5, sha1, sha256, sha512) plus `brix_checksum_plugin <name> <path.so> [parms]`, the `xrootd.chksum` analog against a plain-C ABI. An XrdCks plugin binary is not loadable as-is; port it with `contrib/checksum-plugins/`. |
| XrdFrm/MSS/tape staging ecosystem | Yes | Partial | FRM queue/Tape REST integration, and 2.0 F1–F4 closed most of the staging surface: a durable journal (`brix_frm_queue_path`) replayed at restart, an exec MSS adapter (`brix_frm_stagecmd`, deadline-killed by `brix_frm_copy_timeout`), an external event feed (`brix_frm_stagemsg`), per-space purge rules with an external decider (`brix_frm_purge_policy` + `brix_frm_purge_polprog`) and the dataset seal queue. Not the upstream `frm_admin` / `frm_xfragent` process family or its config grammar; migration policy remains watermark-driven rather than `frm_migr`-shaped. |

## Operations, Observability, and Policy

| Feature | Official XRootD | BriX-Cache | Reviewer notes |
|---|---:|---:|---|
| UDP XrdMon monitoring | Yes | N/A | Explicitly refused for this project. Do not count this as a missing target. |
| Prometheus metrics endpoint | Limited/eos-site dependent | nginx+ | Implemented as a first-class `/metrics` surface. |
| Storage Resource Reporting (SRR) | Limited/eos-site dependent | nginx+ | Implemented in project docs and source. |
| Built-in operations dashboard | No equivalent | nginx+ | Implemented under dashboard/ops docs and module surfaces. |
| Per-identity rate, bandwidth, and concurrency limits | Plugin/config dependent | nginx+ | Implemented through shared-memory policy helpers. |
| Dynamic upstream health/management | Plugin/config dependent | nginx+ | Implemented for this module's nginx deployment model; not a drop-in CMS replacement. |
| Traffic mirroring/shadow replay | No equivalent | nginx+ | HTTP/WebDAV and stream mirror support exists, including opt-in write/data-write mirroring gated by `brix_mirror_writes`. |

## Current Review Hotspots

| Area | Status | Why reviewers should care |
|---|---|---|
| Full XrdFrm/MSS parity | Partial | 2.0 F1–F4 wired the durable queue, the exec MSS adapter, the stage-event feed and the per-space purge grammar, so the knobs an operator sets now do what they say. Sites with tape-backed data services must still validate prepare/evict/cancel semantics against their real tape workflow, and the upstream `frm_*` daemon family has no counterpart here. |
| `host`/`pwd` auth | Implemented | `src/auth/host/` + `src/auth/pwd/`; closed gap. Wire-equivalents, not the `xrdpwdadmin` admin ecosystem. |
| Full `XrdAcc` and *custom* security plugin ecosystem | Partial | BriX-Cache implements practical ACL/token/VOMS controls and all standard auth schemes, but not arbitrary loadable third-party sec plugins. |
| PSS/PFC backends | Missing/partial | Upstream XRootD remains the better fit for deployments built around the PSS/PFC plugin stack, though 2.0 added `pfc.urlcgi` + PSS forwarding (F5). Ceph/RADOS, OssCsi, the OssArc seal and ZIP-member access are implemented in-tree — validate per-site config instead. |
| Native TPC credential edge cases | Partial | Source/destination TPC, TLS-upgraded origins and multihop delegation work; site credential forwarding still needs deployment-specific verification. |
| CRC64 and checksum plugin breadth | Implemented | CRC64/CRC64NVME are built in, and a site algorithm outside the ten built-ins loads through `brix_checksum_plugin` (2.0 F8) wherever a built-in name is accepted. |
| CMS manager/admin feature breadth | Partial | BriX-Cache has manager/upstream controls, but not every upstream CMS admin command or redirection mode. |

## Claims Removed From Older Versions

These statements appeared in older docs and are no longer accurate:

| Old claim | Current source-verified status |
|---|---|
| "Kerberos is not implemented." | Kerberos 5 support exists behind optional build-time support in `src/auth/krb5`. |
| "Official XRootD does not have HTTP-TPC." | Upstream has `src/XrdHttpTpc`; this project should not claim exclusivity for HTTP-TPC. |
| "BriX-Cache lacks HTTP-TPC multistream/performance markers." | Current WebDAV TPC paths implement multistream/range transfer and progress/marker behavior. |
| "Prepare always returns request id 0." | That is only the FRM-off legacy behavior; FRM-enabled operation returns durable request ids. |
| "Write mirroring is out of scope." | Current source has opt-in HTTP/WebDAV write mirroring and stream data-write replay gated by `brix_mirror_writes`. |
| "S3 auth is planned." | S3 SigV4/anonymous auth is implemented under `src/protocols/s3`. |
