# Remaining Gaps vs Official XRootD

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

This document lists features that remain absent or narrower in BriX-Cache after
checking the current module source and the official XRootD source tree under
`/tmp/brix-src`. It deliberately does **not** treat the UDP/XrdMon monitoring
stack as a target: this project has rejected that subsystem and uses
Prometheus/SRR/dashboard/access-log reporting instead.

For the positive feature comparison and source evidence, see
[Source-Verified XRootD Comparison](source-verified-xrootd-comparison.md) and
[XRootD Feature Matrix](xrootd-feature-matrix.md).

## Executive Summary

BriX-Cache is no longer missing the common native data-server surface that
older planning docs described. The current source implements the mainstream
stream protocol lifecycle, active read/write/stat/namespace opcodes, GSI/token/
SSS/unix/krb5/macaroons auth paths, WebDAV, HTTP-TPC, rate/bandwidth/
concurrency controls, traffic mirroring, FRM queue integration, and S3.

The meaningful remaining gaps are concentrated in upstream plugin ecosystems,
legacy or uncommon auth methods, complete tape/MSS semantics, and selected
cluster-manager/admin/proxy behaviors.

## High-Impact Gaps

| Area | Official XRootD | BriX-Cache | Review attention |
|---|---|---|---|
| Full XrdFrm/MSS/tape ecosystem | Full upstream staging, migration, purge, space, and MSS-driver architecture | Durable stage journal (`brix_frm_queue_path`) with restart replay, retry/backoff and dead-letter; `exec`/`hpss`/`cta`/`lib` MSS adapters (`brix_frm_stagecmd`, `brix_frm_copy_timeout`); the `brix_frm_stagemsg` event feed; per-space purge rules and an external decider (`brix_frm_purge_policy`, `brix_frm_purge_polprog`); WLCG Tape REST gateway (2.0 F1-F4) | The knobs now do what they say, but this is not the `frm_admin`/`frm_xfrd`/`frm_purged` daemon family and there is no automatic disk→tape migration scan. Tape-backed sites must still validate `prepare`, `query prepare`, `cancel`, `evict`, purge, and recall behavior against the real storage manager. |
| PSS/PFC proxy storage | Mature PSS and proxy-file-cache stack | `brix_storage_backend root://host:port` and `forward://root[,roots] permit=…` (the client names the origin, XrdPss convention), read-through/slice cache with the `pfc.urlcgi` per-open hints (`brix_cache_urlcgi`) — 2.0 F5; not a full upstream-compatible PSS/PFC replacement | No loadable `pss` plugins, no `pss.*` namespace, no PFC policy engine or cinfo database. Sites that depend on XRootD proxy-cache topology should not assume drop-in parity. |
| Alternative OSS/storage plugins | Ceph/Rados, OssCsi, OssArc, Mirage, and other plugin backends | Storage-driver seam (`src/fs/backend/`) with POSIX, pblock, S3, remote root://, and a striper-interop Ceph/RADOS driver (`rados/sd_ceph*`, phase-60/89 — reads stock XrdCeph on-RADOS data; plus read-only `cephfsro`); CSI page tagstore in `csi_tagstore.c` (phase-59); ZIP-member access in `src/protocols/root/zip/`; the OssArc dataset seal via `tape://<adapter>/<base>?arc=<depth>` (2.0 F3) | Not a loadable OSS plugin host — backends are compiled-in drivers. The remaining hard backend gaps are erasure coding and the object-archive backend; Ceph sites must supply their namelib (lfn2pfn) rule before touching production pools. |
| Full `XrdAcc` privilege model | Upstream access-control plugin semantics | ACL/authdb/VOMS/token-scope controls | Practical policy coverage exists, but reviewers should not assume every upstream privilege and authdb behavior is reproduced. |
| Security plugin ecosystem | Full upstream sec protocol/plugin matrix | Direct implementations for GSI, token, SSS, unix, krb5, macaroons, **pwd**, and **host** | All upstream stream auth schemes now have wire-equivalent implementations (`pwd` in `src/auth/pwd/`, `host` in `src/auth/host/`). Sites using *custom* sec plugins (not these standard schemes) still need a migration plan. |
| Native root TPC edge cases | Broad upstream TPC paths | Partial | Source/destination rendezvous, TLS-upgraded origins (`brix_tpc_outbound_tls`), redirect following (`brix_tpc_max_hops`) and multi-stream pulls (`brix_tpc_streams`) are implemented and tested; site-specific credential forwarding still needs validation per deployment. |
| Checksum plugin breadth | Upstream checksum plugin catalog, including deployment-specific algorithms | Present (2.0) | Ten built-ins (adler32, crc32, crc32c + page CRC, crc64, crc64nvme, zcrc32, md5, sha1, sha256, sha512 — every one of them on the Qconfig `chksum` list clients negotiate from) plus `brix_checksum_plugin <name> <path.so> [parms]`, the `xrootd.chksum` plugin analog: a site algorithm loaded from a shared object against a plain-C ABI (`src/core/compat/checksum_plugin_abi.h`), usable wherever a built-in name is (Qcksum, `brix_checksum_default`, Qconfig `chksum`, WebDAV `Want-Digest`). Existing XrdCks plugins are not binary-compatible and need a thin port to the BriX ABI (`contrib/checksum-plugins/`). |
| CMS manager/admin breadth | Full upstream manager, redirector, and admin command ecosystem | Near-parity manager behaviour (phase-89 closed the opcode matrix: load meter, locate cache, staging forward, rm/rmdir fan-out, blacklist file — all flag-gated) | Multi-tier sub-manager chaining (W7), upstream CMS admin commands, and EC redirect mode remain open. |

## Medium-Impact or Deployment-Specific Gaps

| Area | Status | Notes |
|---|---|---|
| Async attention packets | Partial | Queue/wait behaviors exist where needed, but broad upstream attention semantics should be reviewed per workflow. |
| Extended collection/GPF behavior | Missing | BriX-Cache does not advertise GPF-style collection behavior. |
| `kXR_gpfile` | Unsupported | Upstream default data-server behavior is also unsupported, so this is normally low impact. |
| In-process XrdCl client library | Not applicable | BriX-Cache is a server module and does not replace XrdCl. |
| UDP/XrdMon monitoring | Intentionally absent | Replaced by Prometheus/SRR/dashboard/logs by project policy. |

## No Longer Gaps

The following items were described as missing in older docs, but current source
or source-verified review shows they are implemented:

| Former gap | Current status |
|---|---|
| Kerberos 5 auth | Implemented as optional build-time support in `src/auth/krb5`. |
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

## BriX-Cache Features Not Present Upstream

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
| Does the site depend on PSS, PFC, or custom OSS plugins? | Treat as a blocker or require an architectural replacement. (Ceph/RADOS, ZIP-member access, and the CSI tagstore are now implemented in-tree — validate per-site config instead.) |
| Does the site require full XrdFrm/MSS behavior? | Run real `prepare`/`qprep`/`cancel`/`evict` tests against the tape backend. |
| Does the site use `host`, `pwd`, or custom security plugins? | Keep official XRootD or implement a migration path. |
| Does native TPC require TLS-upgraded origins or multihop delegation? | Both are built in (`brix_tpc_outbound_tls`, `brix_tpc_max_hops`); test with production credential flows, not only anonymous/local copies. |
| Are checksum policies tied to site-specific checksum plugins beyond the built-in set? | Confirm which algorithms clients and catalog policy require; anything outside the ten built-ins is registered with `brix_checksum_plugin` after porting the XrdCks plugin to the BriX ABI (`contrib/checksum-plugins/README.md`). |
| Are CMS admin commands part of operations automation? | Map each command to BriX-Cache manager/upstream behavior before migration. |
