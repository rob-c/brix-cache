# Remaining Gaps vs Official XRootD

Last verified: 2026-06-14

This document lists features that remain absent or narrower in nginx-xrootd after
checking the current module source and the official XRootD source tree under
`/tmp/xrootd-src`. It deliberately does **not** treat the UDP/XrdMon monitoring
stack as a target: this project has rejected that subsystem and uses
Prometheus/SRR/dashboard/access-log reporting instead.

For the positive feature comparison and source evidence, see
[Source-Verified XRootD Comparison](source-verified-xrootd-comparison.md) and
[XRootD Feature Matrix](xrootd-feature-matrix.md).

## Executive Summary

nginx-xrootd is no longer missing the common native data-server surface that
older planning docs described. The current source implements the mainstream
stream protocol lifecycle, active read/write/stat/namespace opcodes, GSI/token/
SSS/unix/krb5/macaroons auth paths, WebDAV, HTTP-TPC, rate/bandwidth/
concurrency controls, traffic mirroring, FRM queue integration, and S3.

The meaningful remaining gaps are concentrated in upstream plugin ecosystems,
legacy or uncommon auth methods, complete tape/MSS semantics, and selected
cluster-manager/admin/proxy behaviors.

## High-Impact Gaps

| Area | Official XRootD | nginx-xrootd | Review attention |
|---|---|---|---|
| Full XrdFrm/MSS/tape ecosystem | Full upstream staging, migration, purge, space, and MSS-driver architecture | Partial FRM queue and WLCG Tape REST gateway | Tape-backed sites must validate `prepare`, `query prepare`, `cancel`, `evict`, purge, and recall behavior against the real storage manager. |
| PSS/PFC proxy storage | Mature PSS and proxy-file-cache stack | Not a full upstream-compatible PSS/PFC replacement | Sites that depend on XRootD proxy-cache topology should not assume drop-in parity. |
| Alternative OSS/storage plugins | Ceph/Rados, OssCsi, Zip, and other plugin backends | POSIX-first backend with selected local helpers | This project should be presented as a high-performance POSIX/nginx module, not a complete OSS plugin host. |
| Full `XrdAcc` privilege model | Upstream access-control plugin semantics | ACL/authdb/VOMS/token-scope controls | Practical policy coverage exists, but reviewers should not assume every upstream privilege and authdb behavior is reproduced. |
| Security plugin ecosystem | Full upstream sec protocol/plugin matrix | Direct implementations for GSI, token, SSS, unix, krb5, macaroons; missing host/pwd | `host` and `pwd` auth remain absent. Sites using custom sec plugins need a migration plan. |
| Native root TPC edge cases | Broad upstream TPC paths | Partial | Basic source/destination rendezvous exists. TLS-upgraded origins, multihop delegation, and site-specific credential forwarding need validation. |
| Checksum plugin breadth | Upstream checksum plugin catalog, including deployment-specific algorithms | Partial | CRC32c/page integrity, checksum query support, CRC-64/XZ, and CRC-64/NVME exist; full upstream plugin-framework breadth is not equivalent. |
| CMS manager/admin breadth | Full upstream manager, redirector, and admin command ecosystem | Partial nginx-oriented manager/upstream controls | Dynamic upstream management exists, but not every CMS admin command, EC redirect mode, or redirector behavior. |

## Medium-Impact or Deployment-Specific Gaps

| Area | Status | Notes |
|---|---|---|
| Async attention packets | Partial | Queue/wait behaviors exist where needed, but broad upstream attention semantics should be reviewed per workflow. |
| Extended collection/GPF behavior | Missing | nginx-xrootd does not advertise GPF-style collection behavior. |
| `kXR_gpfile` | Unsupported | Upstream default data-server behavior is also unsupported, so this is normally low impact. |
| In-process XrdCl client library | Not applicable | nginx-xrootd is a server module and does not replace XrdCl. |
| UDP/XrdMon monitoring | Intentionally absent | Replaced by Prometheus/SRR/dashboard/logs by project policy. |

## No Longer Gaps

The following items were described as missing in older docs, but current source
or source-verified review shows they are implemented:

| Former gap | Current status |
|---|---|
| Kerberos 5 auth | Implemented as optional build-time support in `src/krb5`. |
| UNIX auth | Implemented in `src/unixauth`. |
| XrdHttp/WebDAV basics | Implemented here; upstream also has XrdHttp. |
| HTTP third-party copy | Implemented here; upstream also has `XrdHttpTpc`. |
| HTTP-TPC performance markers/chunked progress | Implemented in current WebDAV TPC paths. |
| HTTP-TPC multistream/range transfers | Implemented in current WebDAV TPC paths. |
| OAuth2/OIDC delegation for WebDAV TPC | Implemented through delegation/token-exchange helpers. |
| Macaroon mint/verify/delegation | Implemented. |
| Rate limiting, bandwidth limits, concurrency limits | Implemented through shared-memory policy modules. |
| Traffic mirroring | Implemented for HTTP/WebDAV and stream surfaces, including opt-in write/data-write replay. |
| `prepare` request id is always `"0"` | Only true when FRM is disabled. FRM-enabled operation uses durable request ids. |
| S3 auth is planned | S3 SigV4/anonymous auth is implemented. |

## nginx-xrootd Features Not Present Upstream

These are not "gaps"; they are project-specific additions that sites may value
when comparing replacement options:

| Feature | Why it matters |
|---|---|
| Unified root/WebDAV/XrdHttp/S3 gateway in nginx | Lets sites consolidate storage access surfaces under nginx operational tooling. |
| Prometheus metrics and operations dashboard | Avoids the UDP monitoring stack and aligns with common cloud-native observability. |
| Storage Resource Reporting | Provides first-class SRR surfaces for site reporting. |
| Per-identity rate, bandwidth, and concurrency policy | Gives operators built-in controls that are harder to standardize across upstream plugin deployments. |
| Traffic mirroring/shadow replay | Allows live comparison before cutover, including gated write replay to isolated shadows. |
| Hardened WebDAV TPC path | Includes SSRF controls, credential handling, progress markers, and multistream/range logic. |
| S3 REST frontend | Adds an object-storage compatible access surface that upstream XRootD does not provide as an equivalent server feature. |
| WLCG Tape REST gateway | Provides an HTTP control-plane integration point, while still requiring review for full tape-stack parity. |

## Reviewer Checklist

Before using this document in a site migration argument, verify these points
against the target deployment:

| Question | Expected review action |
|---|---|
| Does the site depend on PSS, PFC, Ceph, Zip, OssCsi, or custom OSS plugins? | Treat as a blocker or require an architectural replacement. |
| Does the site require full XrdFrm/MSS behavior? | Run real `prepare`/`qprep`/`cancel`/`evict` tests against the tape backend. |
| Does the site use `host`, `pwd`, or custom security plugins? | Keep official XRootD or implement a migration path. |
| Does native TPC require TLS-upgraded origins or multihop delegation? | Test with production credential flows, not only anonymous/local copies. |
| Are checksum policies tied to site-specific checksum plugins beyond the built-in CRC64/CRC64NVME set? | Confirm which algorithms are required by clients and catalog policy. |
| Are CMS admin commands part of operations automation? | Map each command to nginx-xrootd manager/upstream behavior before migration. |
