# XRootD vs nginx-xrootd — the comparison set

A hyper-detailed, **source-grounded** comparison of **official XRootD** (the C++
daemon + plugin ecosystem) against **this nginx-xrootd module** (a C nginx
stream/http module), covering both **codebase internals** (how each feature is
implemented) and the **end-user / administrator view** (config, commands,
observable behaviour, parity).

Every claim in this set is tied to source on **both** sides:
- Official: `/tmp/xrootd-src/src` (the `Xrd*` subsystems).
- This module: `src/` (and `client/`, `shared/xrdproto`).

> **Working assumption** (inherited from the conformance effort): where behaviour
> differs from the reference, it is treated as a bug in *this* module unless there
> is positive evidence the divergence is deliberate. The honest ledger of what is
> fixed, deferred, or by-design lives in
> [11 — Gaps, divergences & extras](./11-gaps-divergences-and-extras.md).

---

## Who should read what

| You are… | Start with |
|---|---|
| A **C++ engineer** reviewing the code | [01 Architecture](./01-architecture-and-process-model.md) → then the [nginx idioms for C++ reviewers](../../../09-developer-guide/nginx-idioms-for-cpp-reviewers.md) primer + the generated Doxygen (`tools/gen-docs.sh`) |
| A **protocol / interop** reviewer | [02 root:// protocol](./02-rootd-protocol.md), [03 Auth](./03-authentication-authorization.md), [conformance-findings](../conformance-findings.md) |
| A **storage / site admin** | [07 Storage/cache/tape](./07-storage-cache-tape.md), [08 Operations](./08-operations-observability.md), [06 Clustering](./06-clustering-redirection-tpc.md) |
| An **end user** (xrdcp/xrdfs/davs/S3) | [02 protocol](./02-rootd-protocol.md) (end-user view), [05 HTTP/WebDAV/S3](./05-http-webdav-s3.md), [09 Clients & tools](./09-clients-and-tools.md) |
| A **security** reviewer | [10 Security & hardening](./10-security-and-hardening.md), [03 Auth](./03-authentication-authorization.md) |
| Deciding **"is this a drop-in?"** | [11 Gaps & drop-in assessment](./11-gaps-divergences-and-extras.md) |

---

## The set

| # | Document | Covers |
|---|---|---|
| 01 | [Architecture & process model](./01-architecture-and-process-model.md) | multi-threaded daemon + plugins vs nginx event-loop workers + module; request lifecycle; memory (pools); build/config model |
| 02 | [root:// binary protocol](./02-rootd-protocol.md) | framing, handshake/login/TLS, **opcode-by-opcode coverage** (32/33 request codes), vendor extensions |
| 03 | [Authentication & authorization](./03-authentication-authorization.md) | GSI/VOMS, bearer tokens (WLCG/SciTokens/macaroon), SSS, krb5, unix, pwd, host; XrdAcc-style ACLs; fail-closed design |
| 04 | [Data plane & performance](./04-data-plane-and-performance.md) | read/readv/pgread, write/pgwrite/sync, AIO + io_uring, sendfile/kTLS, write pipelining, checksums, compression |
| 05 | [HTTP, WebDAV & S3](./05-http-webdav-s3.md) | XrdHttp vs our WebDAV (class 1 **and 2**), HTTP-TPC, the S3 gateway (nginx-forward) |
| 06 | [Clustering, redirection & TPC](./06-clustering-redirection-tpc.md) | CMS/cmsd, manager/redirector + locate, native root:// TPC, proxy mode, traffic mirroring |
| 07 | [Storage, cache & tape](./07-storage-cache-tape.md) | OSS/localroot + the plugin-ABI gap, POSC, xcache (read/write-through), FRM tape staging + WLCG Tape REST |
| 08 | [Operations & observability](./08-operations-observability.md) | config model, **pull-HTTP Prometheus vs push-UDP XrdMon**, SciTags, SRR, logging, health, packaging, rate-limit policy |
| 09 | [Clients & tools](./09-clients-and-tools.md) | the native pure-C `xrdcp`/`xrdfs`/`xrootdfs`/`libxrdc` suite vs `XrdCl` + apps; parity tables; known client gaps |
| 10 | [Security & hardening](./10-security-and-hardening.md) | kernel `RESOLVE_BENEATH` confinement, fail-closed auth, framing robustness, impersonation, OCSP/CRL, build hardening |
| 11 | [Gaps, divergences & extras](./11-gaps-divergences-and-extras.md) | the candid ledger: official-only gaps, nginx-only extras, the full conformance divergence table, drop-in assessment |

---

## Master feature matrix

High-level summary; each cell links to the detailed doc. Legend: **✓** full /
on-par · **◑** partial or narrower · **✗** absent · **➕** nginx-forward (exceeds
or has no upstream equivalent). "Source-verified" — claims are grounded in both
trees; see each doc's *Source references*.

### Core protocol & data

| Capability | Official XRootD | nginx-xrootd | Detail |
|---|---|---|---|
| root:// wire framing & handshake | ✓ | ✓ byte-identical | [02](./02-rootd-protocol.md) |
| Request opcodes implemented | ✓ (reference) | ✓ 32/33 (`kXR_gpfile` is the gap; itself unfinished upstream) | [02](./02-rootd-protocol.md) |
| TLS negotiation (`ableTLS`↔`gotoTLS`) | ✓ | ✓ | [02](./02-rootd-protocol.md) |
| read / readv / pgread (+ per-page CRC32c) | ✓ | ✓ | [04](./04-data-plane-and-performance.md) |
| write / pgwrite / sync | ✓ | ✓ (pgwrite CSE-retransmit ◑ — hard-fail instead) | [04](./04-data-plane-and-performance.md) |
| Async I/O backend | ✓ threads | ✓ thread-pool **+ io_uring** | [04](./04-data-plane-and-performance.md) |
| Write pipelining | ✓ | ✓ | [04](./04-data-plane-and-performance.md) |
| Checksums (adler32/crc32/crc32c/crc64/md5/sha*) | ✓ (plugins; **no crc64 compute**) | ✓ in-tree (incl. crc64 XZ + NVME) | [04](./04-data-plane-and-performance.md) |
| Inline compression (gzip/xz/zstd/brotli/bz2/lz4) | ✗ | ➕ | [04](./04-data-plane-and-performance.md) |

### Authentication & authorization

| Capability | Official | nginx-xrootd | Detail |
|---|---|---|---|
| GSI / x509 / VOMS (+ signed-DH, cipher neg.) | ✓ | ✓ (interops with real EOS/dCache) | [03](./03-authentication-authorization.md) |
| Bearer tokens (WLCG/SciTokens/macaroon) | ✓ (delegates to libs) | ✓ in-process (mandatory-expiry, issuer-pin, L1/L2 cache) | [03](./03-authentication-authorization.md) |
| SSS / krb5 / unix / pwd / host | ✓ | ✓ | [03](./03-authentication-authorization.md) |
| OCSP revocation | ✗ (CRL only) | ➕ OCSP + CRL | [03](./03-authentication-authorization.md), [10](./10-security-and-hardening.md) |
| Authorization (ACL / VO ACL / token scope) | ✓ XrdAcc | ✓ versioned engine, all 3 protocols | [03](./03-authentication-authorization.md) |

### HTTP family

| Capability | Official | nginx-xrootd | Detail |
|---|---|---|---|
| WebDAV class 1 (GET/PUT/PROPFIND/MKCOL/MOVE/COPY/DELETE) | ✓ XrdHttp | ✓ | [05](./05-http-webdav-s3.md) |
| WebDAV class 2 (LOCK/UNLOCK/PROPPATCH) | ✗ | ➕ | [05](./05-http-webdav-s3.md) |
| HTTP third-party-copy (pull/push, multistream) | ✓ | ✓ (+ RFC-8693 delegation, SSRF guard) | [05](./05-http-webdav-s3.md) |
| S3 gateway (SigV4, multipart, ListObjects, conditional) | ◑ (`XrdS3` nascent) | ➕ full server | [05](./05-http-webdav-s3.md) |

### Cluster, storage, operations

| Capability | Official | nginx-xrootd | Detail |
|---|---|---|---|
| CMS/cmsd clustering | ✓ | ◑ (client + manager modes; full real-cmsd interop maturing) | [06](./06-clustering-redirection-tpc.md) |
| Redirector / locate / proxy mode | ✓ | ✓ | [06](./06-clustering-redirection-tpc.md) |
| Native root:// TPC | ✓ (in-proc) | ✓ (cross-process SHM key registry) | [06](./06-clustering-redirection-tpc.md) |
| Traffic mirroring | ✗ | ➕ | [06](./06-clustering-redirection-tpc.md) |
| Pluggable storage backend (OSS .so ABI, ceph, EC) | ✓ | ✗ (single confined local export) | [07](./07-storage-cache-tape.md), [11](./11-gaps-divergences-and-extras.md) |
| xcache (read-through / write-through) | ✓ XrdPfc | ◑ (no per-block prefetch/purge engine) | [07](./07-storage-cache-tape.md) |
| Tape / FRM staging | ✓ (mature 4-daemon FRM) | ◑ (durable queue + WLCG Tape REST; migration/purge are scaffolds) | [07](./07-storage-cache-tape.md) |
| Monitoring | ✓ push-UDP (XrdMon f/g-stream) | ➕ pull-HTTP Prometheus (deliberate) + REST dashboard | [08](./08-operations-observability.md) |
| SciTags packet marking | ◑ (Firefly; IPv6 flow-label TODO upstream) | ✓ Firefly + working IPv6 flow-label | [08](./08-operations-observability.md) |
| Rate limiting / DoS shedding | ◑ (XrdThrottle) | ➕ leaky-bucket by VO/issuer/IP/DN/volume | [08](./08-operations-observability.md), [10](./10-security-and-hardening.md) |
| Native client suite + FUSE | ✓ XrdCl/apps/XrdFfs | ✓ clean-room pure-C (no libXrdCl) + resilient FUSE | [09](./09-clients-and-tools.md) |
| Path confinement | ◑ lexical (rpCheck/Squash) | ➕ kernel-enforced `openat2(RESOLVE_BENEATH)` | [10](./10-security-and-hardening.md) |

---

## Drop-in replacement, at a glance

Detailed per-profile assessment in [11](./11-gaps-divergences-and-extras.md#drop-in-replacement-assessment-by-deployment-profile). Summary:

| Deployment profile | Viability | Main caveat |
|---|---|---|
| WebDAV / HTTP gateway | **Strong** | exceeds upstream (class-2 locking, S3, TPC delegation) |
| S3 gateway | **Strong** (nginx-forward) | no upstream baseline to match |
| Standalone data server (local FS) | **Good** | no pluggable OSS backends (ceph/EC); FRM migration/purge immature |
| xcache | **Good** | no per-block prefetch/purge engine |
| Redirector / proxy | **Good** | full real-`cmsd` cluster interop still maturing |
| Tape endpoint | **Partial** | recall/stage + Tape REST work; migration/purge are scaffolds |
| Site needing UDP XrdMon / MonaLisa | **Not a drop-in** | monitoring is pull-HTTP by deliberate design |

---

## Relationship to the older comparison docs

This set **consolidates and deepens** several earlier, narrower, sometimes
overlapping documents. Those remain for history/cross-reference but this set is
the intended authoritative comparison going forward:

- [`source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md) — the prior source-verified feature matrix (its facts are folded in here).
- [`../xrootd-implementations.md`](../xrootd-implementations.md) — the five-implementation `root://` code-level study (architecture/handshake/security/data-plane); deeper on go-hep/dCache/EOS than this set.
- [`../conformance-findings.md`](../conformance-findings.md) — the live conformance ledger (the test batches that drove the divergence fixes catalogued in [11](./11-gaps-divergences-and-extras.md)).
- [`../gohep-interop-findings.md`](../gohep-interop-findings.md), [`../by-the-numbers.md`](../by-the-numbers.md), and the `../../feature-gaps.md` / `../../gaps-vs-xrootd.md` / `../../source-verified-xrootd-comparison.md` notes.

If a fact here disagrees with an older doc, **this set is newer** — but each claim
is cited, so verify against the named source on either side.
