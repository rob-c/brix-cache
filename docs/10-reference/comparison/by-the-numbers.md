[← Comparison overview](../design-rationale.md)

## By the numbers

The hard data: source size, binary footprint, request throughput, and memory use — nginx-xrootd vs reference xrootd.

### nginx-xrootd source

All figures are for the `src/` tree as of this document's date. The module is
written in C and plugs into nginx's stream and HTTP lifecycles.

| Subsystem | Files | Lines | What it implements |
|---|---|---|---|
| `webdav/` | 63 | 15,641 | HTTP WebDAV handler: GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, OPTIONS, conditional requests, ETag, CORS, TPC pull |
| `s3/` | 26 | 6,862 | S3-compatible path-style endpoint: PutObject, GetObject, HeadObject, ListObjectsV2, DeleteObject, CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload, SigV4 auth |
| `read/` | 23 | 4,152 | Native XRootD read path: kXR_open, kXR_read, kXR_readv, kXR_pgread, kXR_close, fd cache integration, readahead, prefetch |
| `cache/` | 13 | 2,199 | Per-handle open-file metadata cache, LRU eviction, fd-table management, stat cache |
| `write/` | 20 | 2,692 | Native XRootD write path: kXR_write, kXR_writev, kXR_pgwrite, kXR_sync, kXR_truncate, kXR_chkpoint |
| `path/` | 15 | 1,842 | Path resolution and confinement: realpath, prefix checks, directory traversal guards, URL decoding |
| `connection/` | 16 | 1,585 | TCP connection lifecycle, recv/send state machine, session tracking, TLS upgrade, fd helpers |
| `metrics/` | 9 | 1,484 | Prometheus counters for native XRootD, WebDAV, S3; bytes, auth, error, cache, and range counters |
| `gsi/` | 8 | 1,465 | GSI/x509 proxy certificate parsing, chain validation, CRL checking, VOMS AC extraction |
| `token/` | 13 | 1,455 | WLCG/JWT SciToken validation: RS256, nbf/exp/iss/aud claims, scope path matching, JWKS key loading |
| `cms/` | 12 | 1,442 | CMS/manager-mode cluster: heartbeat client, locate redirect, dynamic server registry |
| `aio/` | 8 | 1,433 | Async I/O buffer management: spill-to-file, buffer chain helpers, thread pool integration |
| `query/` | 9 | 1,413 | kXR_query infotypes: Qconfig, Qspace, QFSinfo, Qcksum/adler32, Qvisa, Qopaque, kXR_prepare/staging |
| `tpc/` | 9 | 1,270 | WebDAV HTTP-TPC pull and push: curl subprocess management, header forwarding, SSRF policy |
| `protocol/` | 6 | 1,212 | XRootD wire format: request/response structs, opcode constants, error codes, dlen validation |
| `upstream/` | 9 | 997 | Upstream redirect handling for cluster locate responses |
| `sss/` | 2 | 880 | SSS (shared-secret security) token verification |
| `config/` | 8 | 830 | nginx directive parsing and per-location configuration merge |
| `session/` | 9 | 806 | Per-connection XRootD session state: login, auth, capability bitmask, credential context |
| `fattr/` | 7 | 709 | kXR_fattr extended attribute get/set/list/del handler |
| `handshake/` | 9 | 673 | XRootD protocol handshake and kXR_protocol frame |
| `types/` | 5 | 606 | Shared type definitions, error maps, status codes |
| `dirlist/` | 7 | 582 | kXR_dirlist handler: directory enumeration, kXR_dstat per-entry stat flag |
| `crypto/` | 3 | 534 | PKI consistency checks, CA store construction, CRL load helpers |
| `response/` | 5 | 489 | Response framing helpers: header construction, multi-response chaining |
| `voms/` | 4 | 447 | VOMS extension parsing and VO membership extraction |
| `stream/` | 1 | 414 | nginx stream module entry point and worker context allocation |
| `manager/` | 2 | 447 | Manager-mode cluster coordination (CMS server role) |
| **Total** | **260** | **93,463** | |

The module has no external C dependencies beyond nginx and OpenSSL. No XRootD
libraries are linked: the XRootD wire protocol is implemented directly.

### nginx-xrootd test suite

| Metric | Count |
|---|---|
| Test files | 142 |
| Total test functions | 1,192 |
| Test code (Python lines) | 27,236 |
| Test-to-source ratio | ~0.72 lines of test per line of source |

Tests run against real nginx processes under the module. There are no mocks of
the nginx core or the filesystem. The suite exercises:

- native XRootD wire protocol against `NGINX_ANON_PORT` (11094),
  `NGINX_GSI_PORT` (11095), and `NGINX_SSS_PORT` (11096)
- WebDAV over HTTPS on `NGINX_WEBDAV_PORT` (8443) and plain HTTP on
  `NGINX_HTTP_WEBDAV_PORT` (8080)
- the S3-compatible endpoint
- token and GSI authentication including CRL, VOMS, algorithm-confusion and
  scope-path-boundary attacks
- wire-level malformed input: oversized `dlen`, unknown opcodes, partial
  handshakes, pre-auth opcode injection
- concurrent and throughput scenarios

The test count exceeds the equivalent coverage shipped with the xrootd v5/v6
client and server tests for the POSIX data-server use case by a substantial
margin. The upstream test infrastructure covers a broader feature surface but
does not include comparable targeted security and protocol-edge cases for the
specific read/write/auth paths exercised here.

### Upstream XRootD footprint for context

The upstream `xrootd/xrootd` repository's `src/` directory spans several
hundred C++ source and header files organized across storage backends (OFS,
OSS), cluster management (CMS), proxy services (PSS), caching (PFC), file
residency management (FRM), HTTP (XrdHttp), security plugins (XrdSec,
XrdSecgsi, XrdSecpwd, XrdSeckrb5), the XRootD client library (XrdCl),
monitoring (XrdMon), and supplementary protocols (XrdTpc, XrdSsi). By raw line
count the upstream source tree is approximately an order of magnitude larger
than this module.

That breadth reflects XRootD's design as a general-purpose framework.
`nginx-xrootd` covers the practical data-server subset — local POSIX, native
`root://`, WebDAV, S3-compatible HTTP, and current grid auth — in roughly
38 kloc of C with a purpose-built nginx event model instead of a full
independent server runtime.

```text
scope comparison (approximate)

    upstream XRootD source tree       ~380,000 lines C++
    nginx-xrootd source               ~38,000 lines C
    ─────────────────────────────────────────────────────
    ratio                             ~10×

    nginx-xrootd tests                1,192 collected, integration-level,
                                      no mocks, security and edge-case focus
```

These numbers are not a quality judgement — they reflect design scope. The
upstream project targets every XRootD deployment shape; this module targets
one well-defined shape and aims to be auditable at that scope.

## Developer investment — estimated hours

This section estimates the cumulative developer hours required to build and
maintain each project. These are engineering estimates, not audited figures.
They are useful for understanding the economic and human cost of the design
choices each project makes, and for setting realistic expectations when
planning contributions.

---

### nginx-xrootd

**Initial implementation (estimated 4,500–6,000 hours)**

The module is ~38,000 lines of C source plus ~27,000 lines of Python tests —
~65,000 lines total at high average complexity. Every subsystem required deep
protocol knowledge, reverse-engineering of undocumented wire behavior, and
careful integration with nginx internals.

| Subsystem | Estimated hours | Why it is expensive |
|---|---:|---|
| XRootD wire protocol, state machine, framing | 400–600 | 24 non-obvious protocol notes (see `docs/protocol-notes.md`); handshake format differs from spec |
| Native read path (open/read/readv/pgread/stat/close) | 500–700 | pgread is the most complex opcode: `kXR_status` response, per-page CRC32c, thread-pool integration |
| Native write path (pgwrite/writev/chkpoint/sync/truncate/mkdir/rm/mv/chmod) | 400–500 | pgwrite CRC verification and the 32-byte `kXR_status` response shape are easy to get wrong |
| GSI/x509 authentication | 500–700 | DH key exchange from scratch; proxy certificate chain; VOMS AC extraction; 5 non-obvious DH/OpenSSL quirks |
| JWT/WLCG token validation and JWKS | 300–400 | JOSE parsing, RS256 verify, scope path semantics, `wlcg.groups` |
| Macaroon tokens | 150–200 | HMAC-SHA256 chain, ISO8601 timestamps, activity caveat semantics |
| WebDAV (all RFC 4918 methods + CORS + auth + TPC + metrics) | 700–1,000 | 29 source files; RFC compliance for COPY, MOVE, LOCK, PROPFIND; TPC push/pull with credential delegation |
| S3-compatible endpoint + multipart | 300–450 | SigV4 auth, ListObjectsV2 XML, multipart part staging with atomic assembly |
| HTTP-TPC (pull + push + OAuth2/OIDC delegation) | 300–400 | curl subprocess management, SSRF policy, RFC 8693 token exchange, oidc-agent IPC |
| Native root:// TPC (shared-memory key registry + pull client) | 500–650 | Shared-memory key registry, outbound auth, thread-pool pull client, manager redirect |
| kXR_bind parallel streams with shared handle table | 250–350 | Cross-worker handle visibility via shared-memory table, dev/ino validation |
| CMS heartbeat + manager/cluster mode | 400–500 | CMS binary framing, dynamic server registry, locate redirect logic |
| nginx AIO thread-pool integration | 200–300 | Thread-safe AIO context management; destroyed-connection guard pattern |
| Prometheus metrics (all subsystems) | 150–200 | Shared-memory atomic counters, low-cardinality label discipline |
| Path confinement + access logging | 150–200 | realpath-based confinement, log injection prevention |
| Tests — 1,192 integration tests, no mocks | 700–900 | Real nginx processes, real PKI, security edge cases, protocol adversarial tests |
| Documentation (architecture, protocol notes, comparison, per-subsystem) | 350–500 | |
| Debugging, integration, security review | 450–600 | Protocol conformance testing against reference xrootd; security probe harness |
| **Total** | **~4,550–6,250** | |

**Ongoing maintenance (estimated 600–1,200 hours/year)**

| Work category | Hours/year |
|---:|---|
| Protocol conformance updates as upstream XRootD evolves | 100–200 |
| Security review (auth, token, path confinement) | 100–150 |
| New feature development (see `docs/feature-roadmap.md`) | 200–400 |
| Test maintenance and expansion | 100–200 |
| Operator support and documentation updates | 100–250 |

At a market rate of **$150–250 per hour** for a senior HEP storage systems engineer (C, nginx internals, grid security, cryptographic protocols), the initial build represents a replacement cost of roughly **$680,000–$1,560,000**. Ongoing maintenance runs at roughly **$90,000–$300,000 per year**.

---

### Official XRootD

**Cumulative investment (estimated 100,000–250,000 hours, 2004–2026)**

The upstream `xrootd` project has been under continuous development for over
20 years at SLAC, CERN, Fermilab, and collaborating institutions. The source
tree spans ~380,000 lines of C++ across storage backends (OFS, OSS), cluster
management (CMS, FRM), proxy services (PSS), caching (PFC), HTTP (XrdHttp),
security plugins (XrdSec, XrdSecgsi, XrdSecpwd, XrdSeckrb5, SciTokens,
Macaroons), the XRootD client library (XrdCl), monitoring (XrdMon), and
supplementary protocols (XrdTpc, XrdSsi).

| Period | Team size (estimate) | Annual hours | Cumulative |
|---|---:|---:|---:|
| 2004–2010 (SLAC-led foundation) | 3–5 FTE | 4,500–7,500 | 27,000–52,500 |
| 2010–2016 (CERN/Fermilab adoption, rapid growth) | 5–10 FTE | 7,500–15,000 | 45,000–90,000 |
| 2016–2022 (SciTokens, Macaroons, HTTP-TPC, modern auth) | 5–8 FTE | 7,500–12,000 | 45,000–72,000 |
| 2022–2026 (v5/v6, XrdClS3, continued development) | 4–7 FTE | 6,000–10,500 | 24,000–42,000 |
| **Total** | | | **~141,000–256,500** |

Applying a blended institutional rate of **$100–180 per hour** (engineers at
national labs and CERN often have different cost structures than commercial
software), the cumulative investment in XRootD represents roughly
**$14,000,000–$46,000,000** in engineering value.

**Ongoing maintenance (estimated 7,500–15,000 hours/year)**

The project currently involves active contributors from CERN, SLAC, and partner
institutions running ~5–10 FTE of engineering effort, working on new protocol
features, security updates, client library enhancements, storage backend
integrations, and deployment support for the WLCG collaboration.

---

### What the numbers mean for contributors

| Question | nginx-xrootd | Official XRootD |
|---|---|---|
| How many hours to understand the whole codebase? | 40–80 hours (38 kloc, clean separation) | 200–500 hours (380 kloc, broad plugin ecosystem) |
| How many hours to add a new native opcode? | 8–20 hours (see `docs/contributing.md` §1) | 20–60 hours (need to understand OFS/OSS plugin chain) |
| How many hours to add a new WebDAV method? | 4–12 hours (see `AGENTS.md` Recipe A) | 20–80 hours (XrdHttp plugin architecture) |
| How many hours to add a new Prometheus metric? | 2–4 hours | Needs external XrdMon integration (hours to weeks depending on site setup) |
| How many hours to run the full test suite? | 5–15 minutes (automated, local) | Hours to days (broad integration test infrastructure) |
| Can an AI coding agent contribute usefully in one session? | Yes — see `AGENTS.md` | Unlikely without deep XRootD ecosystem context |

The design thesis of this project is captured in that last row: a narrower,
well-documented codebase lets contributors of all kinds — new engineers,
occasional contributors, and AI coding agents — make meaningful progress with
hours of investment rather than weeks. That is not a claim about code quality;
it is a claim about contribution friction.

---
