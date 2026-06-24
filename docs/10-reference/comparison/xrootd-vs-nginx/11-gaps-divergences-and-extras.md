# Gaps, Divergences, and Extras — the candid ledger

> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

This is the honest accounting document of the comparison set. It states three
things plainly, each grounded in source on both sides:

1. What **official XRootD** has that this nginx-xrootd module does **not**.
2. What this module has that **official XRootD does not** (or does not ship as a
   server feature).
3. The catalogue of **known protocol/behavior divergences** surfaced by
   differential conformance testing — most fixed, the remainder listed honestly
   with status and severity.

The working rule throughout: **a divergence from the reference is a bug in this
module unless there is positive evidence otherwise.** Where a claim could not be
verified against source, it is marked "not verified" rather than asserted.

This document consolidates and reconciles the authoritative inputs — it does not
contradict them. Source-of-truth references:

- [`source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md)
- [`gaps-vs-xrootd.md`](../../gaps-vs-xrootd.md)
- [`feature-gaps.md`](../../feature-gaps.md)
- [`protocol-gaps-vs-xrootd.md`](../../protocol-gaps-vs-xrootd.md)
- [`conformance-findings.md`](../conformance-findings.md)
- [`gohep-interop-findings.md`](../gohep-interop-findings.md)

Official source is the checkout at `/tmp/xrootd-src/src` (protocol version
`5.2.0`, advertised in `XProtocol/XProtocol.hh`). This module's source is
`src/` in this repository.

---

## Scope

This document covers feature-level and behavior-level differences. It does **not**
re-derive the positive opcode/auth/HTTP parity matrices — those live in
[`protocol-gaps-vs-xrootd.md`](../../protocol-gaps-vs-xrootd.md) and
[`source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md).
Here we concentrate on the deltas a reviewer must weigh before a migration
decision.

Two scoping decisions are deliberate and stated up front so they are not
mistaken for oversights:

- **UDP XrdMon monitoring is an explicit non-goal**, not a gap. This project
  rejects the fire-and-forget UDP summary/detail (`f`/`g`) stream stack and
  replaces it with HTTP-native observability (Prometheus, SRR, dashboard,
  access logs). It is listed below under official-only features for completeness,
  but it is "by design absent," not "missing."
- This module is a **server/gateway**. It does not attempt to replace the
  upstream client SDK (`XrdCl`, `XrdPosix`) as an in-process library, although it
  *does* ship its own independent native client suite (see extras). Client-SDK
  features are "not replacement-scope," not gaps.

What "drop-in" means here is assessed per deployment profile in the final
section — there is no single yes/no answer.

---

## Official-only features (gaps in nginx-xrootd)

Each item below was confirmed present in the official source tree and **not**
found as a comparable implementation in `src/`. For each: what it is, why it
matters, deployment impact, and whether a partial or HTTP-based alternative
exists here.

### Pluggable OSS / storage plugin ABI

- **Official:** `XrdOss`/`XrdSfs` define a plugin ABI (`XrdVersionPlugin.hh`)
  so storage backends load as `.so` modules at runtime. The whole backend
  ecosystem below depends on it.
- **Here:** POSIX-first backend in `src/fs/` with confined-path helpers; no
  third-party-loadable OSS plugin ABI.
- **Why it matters / impact:** sites that run a non-POSIX or vendor OSS plugin
  cannot drop in. There is no general extension point to add a backend without
  modifying module source.
- **Alternative:** none for the ABI itself. POSIX/CephFS/parallel-FS mounts can
  be exported through the normal POSIX path, which covers many cases but is not
  plugin parity.

### Erasure coding (`XrdEc`)

- **Official:** `XrdEc/` (`XrdEcReader`, `XrdEcStrmWriter`,
  `XrdEcRedundancyProvider`, …) implements stripe/parity erasure-coded objects,
  paired with the `kXR_ecRedir`/`kXR_ecredir` redirect flags.
- **Here:** no erasure-coding layer. `kXR_ecRedir` is defined in
  `src/protocol/flags.h` but **never set** (asserted by tests).
- **Why it matters / impact:** EC-backed XRootD sites (durable object storage
  without full replication) cannot be served. This is a hard blocker for those
  deployments.
- **Alternative:** none. Out of scope without a storage layer that does EC.

### Ceph / RADOS backend (`XrdCeph`)

- **Official:** `XrdCeph/` is a RADOS-native OSS backend.
- **Here:** no Ceph/RADOS OSS plugin. (`source-verified` "Missing".)
- **Why it matters / impact:** Ceph-backed XRootD sites cannot drop in at the
  plugin level.
- **Alternative:** export CephFS over POSIX externally; this is an architecture
  change, not plugin parity.

### Parallel Storage Service / proxy storage (`XrdPss`, full `XrdPfc`)

- **Official:** `XrdPss/` (parallel storage / remote federation backend) and
  `XrdPfc/` (the full proxy-file-cache / XCache policy engine with purge,
  snapshot, resource monitoring).
- **Here:** `src/cache/` provides a practical read-through/slice cache with
  eviction and write-through helpers and advertises `kXR_attrCache`; `src/proxy/`
  + `src/upstream/` provide protocol-bridge proxying. This is **not** a
  full PSS/PFC replacement.
- **Why it matters / impact:** sites depending on XCache purge/snapshot/policy
  internals or PSS remote-fill-as-storage need explicit review. Do not assume
  XCache drop-in parity.
- **Alternative:** partial — cache mode and proxy mode exist and are usable for
  simpler topologies.

### Full FRM / MSS tape ecosystem (`XrdFrm`, `XrdOssArc`, `XrdOssMSS` drivers)

- **Official:** `XrdFrm/` is a complete daemon ecosystem (`frm_admin`,
  `frm_purged`, `frm_xfrd`, `frm_xfragent`, migrate/purge/transfer queue), plus
  `XrdOssArc/` archive integration and MSS driver abstractions.
- **Here:** `src/frm/` is a durable staging queue (file = truth + SHM cache),
  residency xattrs, stage worker, scheduler, metrics, and a WLCG Tape REST
  gateway (`src/webdav/tape_rest.c`). Migrate/purge is scaffold/stub per docs.
  `kXR_prepare`/`kXR_QPrep` work in both an FRM-off legacy mode and an FRM-on
  durable-reqid mode.
- **Why it matters / impact:** this is a serious tape **gateway**, not the full
  upstream FRM **daemon** ecosystem. Tape sites with upstream FRM operational
  workflows (in-process migrate, watermark GC, MSS driver plugins) are **not**
  drop-in.
- **Alternative:** partial and substantial — durable queue + Tape REST cover
  modern HTTP tape control; validate `prepare`/`query prepare`/`cancel`/`evict`/
  recall against the real storage manager before relying on it.

### UDP summary + detail monitoring (`XrdMon` f/g-stream)

- **Official:** `XrdXrootd/XrdXrootdMon*` (`XrdXrootdMonitor`, `MonFile`,
  `MonFMap`, `TpcMon`, `ConfigMon`) emit the UDP summary (`f`) and detailed
  (`g`) monitoring streams consumed by the grid XrdMon collector ecosystem.
- **Here:** **intentionally absent** by project policy.
- **Why it matters / impact:** sites whose accounting/monitoring pipeline
  consumes the UDP XrdMon feed will not receive it. This is the one item where
  the gap is a deliberate product decision, not an incomplete implementation.
- **Alternative:** yes, and it is the recommended path — Prometheus pull metrics
  (`src/metrics/`), WLCG SRR (`src/srr/`), the live dashboard (`src/dashboard/`),
  and structured access logs. Per-file/per-user/per-redirect/per-TPC event
  granularity that XrdMon emits over UDP is **not** reproduced; aggregate
  counters and histograms are.

### Name-to-name mapping (`XrdN2N`)

- **Official:** `XrdOuc/XrdOucN2NLoader` + `XrdOucN2No2p` provide a pluggable
  logical-to-physical name translation layer (LFN↔PFN), used by many sites to
  decouple the exported namespace from on-disk layout.
- **Here:** **not verified present.** The module uses confined-path resolution
  (`src/path/`, `ngx_http_xrootd_webdav_resolve_path()`) and per-export root
  prefixing, but no general pluggable N2N translation layer was found.
- **Why it matters / impact:** sites that rely on an N2N plugin to remap names
  (e.g. hash-spread directory layouts) need to reproduce that mapping by export
  configuration or accept a behavior change.
- **Alternative:** partial — static export roots and path rules cover simple
  cases; arbitrary programmable N2N does not have an equivalent.

### Bandwidth manager (`XrdBwm`) and throttle (`XrdThrottle`) plugin parity

- **Official:** `XrdBwm/` (reservation-style bandwidth manager) and
  `XrdThrottle/` (request-rate plugin).
- **Here:** `src/ratelimit/` implements cross-protocol, identity-aware
  request-rate, bandwidth, and concurrency limits (`xrootd_rate_limit_zone`,
  `xrootd_rate_limit_rule`, `xrootd_bandwidth_limit`,
  `xrootd_concurrency_limit`). This is arguably **more** capable for the common
  case (see extras), but it is **not** the `XrdBwm`/`XrdThrottle` plugins and
  does not reproduce their exact reservation/admin semantics or config model.
- **Why it matters / impact:** automation that drives `XrdBwm`/`XrdThrottle`
  admin behavior will not port directly; the *capability* is present, the
  *plugin contract* is not.
- **Alternative:** yes — the built-in shaping is the intended replacement, just
  not API-compatible.

### Diagnostics filesystem (`XrdDig`)

- **Official:** `XrdDig/` exposes a controlled diagnostics filesystem
  (`XrdDigFS`, `XrdDigAuth`, `XrdDigConfig`) for remote inspection of config/log
  files.
- **Here:** no equivalent diagnostics-FS surface.
- **Why it matters / impact:** sites using `XrdDig` for remote diagnostics lose
  that mechanism.
- **Alternative:** partial — the HTTP dashboard/admin API
  (`src/dashboard/`) and nginx logs cover much of the operational-introspection
  intent through a different surface.

### ZIP virtual filesystem (`XrdZip`) and replica/memory caches (`XrdRmc`, `XrdFrc`)

- **Official:** `XrdZip/` (serve members of a ZIP archive as files), `XrdRmc/`
  (remanufactured memory cache), `XrdFrc/` (file replica catalog).
- **Here:** none of these have a comparable implementation.
- **Why it matters / impact:** specialized; not needed for most HEP replacement
  targets, but a hard miss where used.
- **Alternative:** none.

### Legacy auth plugins: `pwd` and `host`

- **Official:** `XrdSecpwd/` (encrypted password-file ecosystem with
  `xrdpwdadmin`, server public keys, crypto negotiation) and the built-in
  `host` protocol (`XrdSec/XrdSecProtocolhost.cc`, trusted-network auth).
- **Here:** **neither is implemented.** GSI, SSS, unix, krb5, ZTN/WLCG tokens,
  SciTokens, and macaroons are.
- **Why it matters / impact:** `pwd`-auth or `host`-auth legacy sites cannot
  drop in. A plaintext/system-password substitute for `pwd` would be a security
  regression and is deliberately not provided.
- **Alternative:** none by design; migrate to a modern auth method.

### Full `XrdAcc` privilege model

- **Official:** `XrdAcc/` rich auth-file syntax: identity classes, templates,
  exclusive-list behavior, full privilege grammar.
- **Here:** `src/path/authdb.c` — user/group/principal/host rules, longest-prefix
  matching, rw/admin-like privilege bits, VO/token-scope gates. Practical, but
  **not** every upstream `XrdAcc` identity class/template/exclusive-list
  behavior.
- **Why it matters / impact:** complex existing `XrdAcc` files may need
  translation; not all upstream privilege semantics are reproduced.
- **Alternative:** partial — a migration/translation effort, not a clone.

### Full SciTokens / `XrdSecztn` and checksum-plugin breadth

- **Official:** `XrdSciTokens/` broader issuer/config/helper/monitor model;
  `XrdCks/` plugin framework for site-specific checksum algorithms.
- **Here:** `src/token/` validates WLCG/JWT + path scopes;
  `src/compat/checksum.c` + `src/compat/crc64.c` cover adler32, crc32, crc32c,
  md5, sha1, sha256, CRC-64/XZ, CRC-64/NVME. No general checksum **plugin
  framework**.
- **Why it matters / impact:** sites using advanced SciTokens issuer config or a
  site-specific checksum plugin beyond the built-in set need review.
- **Alternative:** partial — the common algorithms and WLCG-token cases are
  covered directly; uncommon plugins are not.

### `XrdOssCsi` checksum/tagstore

- **Official:** `XrdOssCsi/` persistent page-checksum/tagstore.
- **Here:** file-level checksum helpers + xattr-cached integrity + paged wire
  CRC32c; no persistent checksum-index/tagstore parity.
- **Impact:** persistent page-integrity tagstore workflows differ.
- **Alternative:** partial (paged wire CRC exists; the on-disk tagstore does not).

### Other verified-absent items (lower impact)

- **`kXR_gpfile` / GPF (grouped parallel fetch):** defined upstream but the
  upstream **default handler also returns `kXR_Unsupported`**; here it is defined
  and not dispatched, and GPF flags (`kXR_supgpf`/`kXR_anongpf`/`kXR_tlsGPF`)
  are never advertised. **Not a practical gap** — correct behavior is to not
  advertise unimplemented GPF.
- **CMS admin socket / virtual node ID / full CMS tooling:** practical
  manager/redirector/locate/blacklist/metrics exist (`src/cms/`,
  `src/manager/`); the full upstream CMS admin command ecosystem does not.
- **`XrdClRecorder` (client record/replay):** **not verified** — no
  corresponding file found in this `XrdCl` checkout; it is a client-side tool
  regardless and out of replacement scope.
- **`XrdSsi` (storage server interface), `XrdSfs` Spectrum-Scale specifics:**
  no equivalents; specialized.

---

## nginx-only / nginx-forward features

These are not in official XRootD as server features (or are materially more
operator-friendly here). They are the substance of the replacement argument
beyond "same protocol, different daemon." Each is source-grounded.

| Feature | Source evidence | What it adds |
|---|---|---|
| **S3-compatible REST server** | `src/s3/` (`handler.c`, `auth_sigv4_*`, `get.c`, `put.c`, `list_objects_v2.c`, `multipart_*`, `copy.c`, `delete_objects.c`, browser POST) | A full S3 server endpoint over the same namespace: SigV4 (header + presigned), multipart, CopyObject, DeleteObjects, POST Object, OPTIONS/CORS, conditional GET/PUT, CRC64NVME checksums. Upstream ships `XrdClS3` (a **client** plugin), not an S3 REST server. One of the strongest module-only features. |
| **Traffic mirroring / shadow replay** | `src/mirror/`, `src/mirror/stream_wmirror.c` | Shadow live reads and (gated) writes to an isolated backend to validate a candidate before cutover, logging divergence. No comparable upstream server subsystem found. A first-class migration tool. |
| **Inline compression** | `src/compat/codec_{zlib,zstd,brotli,bzip2,lz4,lzma}.c`, `codec_core.c`, `http_compress.c` | gzip/xz/zstd/brotli/bzip2/lz4 across root/WebDAV/S3 and the client, in all four directions (encode/decode on read/write). |
| **Prometheus pull metrics** | `src/metrics/`, `/metrics` endpoint | Low-cardinality counters and latency histograms across stream/WebDAV/S3/rate-limit/cache/FRM/mirror/cluster — the intended replacement for UDP XrdMon. |
| **Leaky-bucket rate / bandwidth / concurrency limiting** | `src/ratelimit/`, `src/metrics/ratelimit.c` | Identity-aware (VO, issuer, DN hash, IP, volume prefix) request-rate, bandwidth, and concurrency shaping across **both** stream and HTTP surfaces — broader and more uniform than per-plugin `XrdThrottle`/`XrdBwm`. |
| **REST admin + live dashboard** | `src/dashboard/` (`api_admin.c`, `api.c`) | HTTP-inspectable transfer/cluster/cache/rate-limit/config state; admin write API with auth/cookie/HMAC paths; config download with fail-closed redaction. |
| **WLCG Storage Resource Reporting (SRR)** | `src/srr/` (`builder.c`, `handler.c`, `module.c`) | First-class HTTP/JSON SRR endpoint for site accounting/discovery; no core upstream server equivalent in the reviewed tree. |
| **Resilient pure-C native client suite + FUSE** | `client/apps/` (`xrdcp`, `xrdfs`, `xrddiag`, `xrdmapc`, `xrdprep`, `xrdgsiproxy`, `xrdadler32`, `xrdcrc32c`, `xrdcrc64`, `xrdsssadmin`, …), `client/lib/`, `xrootdfs*` FUSE | A clean-room `libxrdc`-based client + FUSE driver with connect-vs-IO timeouts, fast-fail on permanent errors, IPv6→IPv4 auto-downgrade, atomic/cancellable transfers. Independent of `libXrdCl`. (Server-replacement scope aside, this is a genuine module-family extra.) |
| **HTTP-based SciTags packet marking** | `src/pmark/` (`firefly.c`, `flowlabel.c`, `scitag.c`, `mapping.c`) | Firefly UDP + IPv6 flow-label packet marking integrated with WebDAV/TPC; an HTTP-native marking path rather than a separate daemon. (Upstream also has `XrdNetPMark`; the surfaces differ.) |
| **Unified multi-protocol namespace under nginx** | shared `src/path/` + `src/read/` + `src/webdav/` + `src/s3/` | One export serves `root://`, `davs://`/XrdHttp, and S3 with **common confinement and policy rules** and one set of nginx operational tooling (certs, reload, logging, reverse proxy). |
| **WebDAV beyond upstream XrdHttp's method set** | `src/webdav/lock.c`, `dead_props.c`, `search.c`, `acl.c`, `methods_basic.c` | `LOCK`/`UNLOCK`, `PROPPATCH` + dead-property storage (xattrs), `SEARCH` (RFC 5323), `ACL` discovery — needed by desktop WebDAV clients that treat `501` as fatal. Not found as server methods in the reviewed XrdHttp source. |
| **Hardened HTTP-TPC** | `src/webdav/tpc_curl.c`, `tpc_cred.c`, `tpc_marker.c`, `tpc_headers.c` | SSRF/DNS-pinning controls, OIDC/RFC-8693 credential delegation, marker streaming, `curl_multi` multistream, dashboard visibility, low-cardinality metrics. Upstream **also** has HTTP-TPC (`XrdHttpTpc`); nginx's edge is hardening + integration, **not** the existence of HTTP-TPC. |
| **WLCG Tape REST gateway** | `src/webdav/tape_rest.c` + `src/frm/` | FTS/gfal2-friendly HTTP tape control sharing the same durable stage queue as native `prepare`/`open`. |
| **Path-confinement discipline** | `src/path/`, `src/compat/namespace_ops.c`, `xrootd_open_confined_canon()` | Every wire path resolves/canonicalizes/confines (`openat2(RESOLVE_BENEATH)`) before any syscall — an auditability advantage. |

Honesty notes for this section: rate limiting, HTTP-TPC, XrdHttp, krb5, unix
auth, macaroon delegation, and IPv6 are **not** module-exclusive — upstream has
them too. The exclusive items are the S3 server, traffic mirroring, SRR, the
Prometheus/dashboard observability model, inline compression, and the
WebDAV-method extensions. Do **not** claim upstream lacks HTTP-TPC.

---

## Known behavioral divergences (conformance ledger)

This is the differential-testing ledger: divergences from the reference
implementation (stock `xrootd` 5.9.5 + `xrdfs`/`xrdcp`) and independent clients
(go-hep) found across three test batches and the go-hep interop pass. Most are
**fixed** (each pinned by a guarding test); the remainder are **deferred** or
**by-design** and listed honestly.

Severity key: **High** = data-loss or breaks-stock-clients; **Med** = visible
interop break for some ops/clients; **Low** = edge/cosmetic.

### Fixed this session (and prior batches) — each has a guarding test

| # | Area | Official / reference behavior | Was (our bug) | Status | Severity | Found by |
|---|---|---|---|---|---|---|
| 1 | `kXR_sigver` | No response on success (it is a request *prefix*); only `kXR_SigVerErr` on failure | Server ACKed it; client read the ack (consistent-but-nonstandard pair) | FIXED (`src/session/signing.c`, `client/lib/sigver.c`) | High | go-hep |
| 2 | `stat`/`dirlist` redirect | All ops consult the redirect map | Only `open`/`locate` used the static `manager_map` | FIXED (`src/read/stat.c`, `src/dirlist/handler.c`) | High | go-hep (mesh) |
| 3 | Root `/` prefix match | A prefix ending in `/` matches everything beneath | `/` matched only `/`, not `/child` | FIXED (`src/path/find_rule.c`) | High | go-hep (mesh) |
| 4 | Unknown opcode | `kXR_InvalidRequest` (3006) | `kXR_Unsupported` (3013) | FIXED | Low | conformance |
| 5 | `kXR_statx` framing | 1 flag byte/path; newline-separated request | 4 bytes + text line; `\0`-separated request | FIXED | Med | conformance |
| 6 | `kXR_query` Qconfig | Bare `value\n`; echo-key for unknown; `bind_max` | `key=value` | FIXED | Med | conformance |
| 7 | `kXR_open` reply | 4-byte fhandle unless retstat/compress | Always 12-byte body | FIXED | High | conformance |
| 8 | `statvfs` reply | 6-field `nRW freeRW utilRW nStg freeStg utilStg` via `statvfs(2)` | 4-field line (stock client: "Invalid response") | FIXED | Med | stock `xrdfs` |
| 9 | dirlist namespace | internal artifacts hidden | leaked `.nginx-xrootd*` internal files | FIXED | Low | stock `xrdfs` |
| 10 | `kXR_stat` flags | Full `StatGen`: `kXR_writable`/`kXR_xset` from perms vs server euid/egid | Only `kXR_readable`(+`kXR_isDir`) | FIXED (`xrootd_stat_flags_from_stat`) | Med | stock `xrdfs stat` |
| 11 | `mkdir` of existing path (no `-p`) | `kXR_ItExists` "file exists" (mkpath stays idempotent) | Silent success | FIXED | Med | stock `xrdfs mkdir` |
| 12 | `query config pio_max` | Bare integer (`maxPio+1`) | Echoed the key | FIXED | Low | stock `xrdfs query` |
| 13 | create-open to missing parent | Parent chain auto-created when `kXR_mkpath \| kXR_async` set (Xeq:1544) | First `NotFound`, then over-generalized to unconditional | FIXED (superseded by #21) | Med | stock `xrdcp` |
| 14 | `kXR_mv` into missing parent | Dest parent chain auto-created; source-missing wording aligned | `kXR_NotFound` | FIXED | Med | stock `xrdfs mv` |
| 15 | Interior `..` segment | Rejected for extract-based ops (stat/open/dirlist/locate) — reference does not normalize `..` | Silently normalized by RESOLVE_BENEATH | FIXED (`xrootd_reject_dotdot_path`) | Med | stock `xrdfs`/`xrdcp` |
| 16 | `query checksum ?cks.type=<algo>` as last CGI field | Trailing NUL/CR/LF trimmed before algo lookup | Wire NUL folded into algo name → "unknown algorithm" (broke non-adler32 + `xrdcp --cksum`) | FIXED | High | stock `xrdfs`/`xrdcp` |
| 17 | `kXR_statx` of missing path | `kXR_error`/`kXR_NotFound` (offline is only for a successful stat with mode==-1) | `kXR_ok` + `kXR_offline` byte | FIXED | Med | stock raw-wire |
| 18 | `kXR_rm` of a **directory** | unlink file / non-recursive rmdir (empty→ok, non-empty→ENOTEMPTY); `osFS->rem` never recurses | **Recursively deleted the whole subtree (DATA LOSS)** | FIXED | **High (critical)** | stock raw-wire + xrdfs |
| 19 | `mkdir /d/` (trailing slash) | Normalized (stripped) like reference Squash → created | `kXR_ArgInvalid` | FIXED | Med | stock `xrdfs mkdir` |
| 20 | `open(kXR_new)` on existing file | `kXR_ItExists` (3018) — EEXIST mapping | `kXR_FileLocked` (3003) | FIXED | Med | stock raw-wire |
| 21 | create-open parent auto-create condition | Gated on `kXR_mkpath \| kXR_async` (XProtocol bit 0x40); xrdcp sets `kXR_async` so uploads work, raw `open(new)` without either correctly fails NotFound | (1st pass) unconditional creation | FIXED (corrects #13) | Med | stock raw-wire + xrdcp |
| 22 | client `xrdfs chmod rwxr-xr-x` | Accepts the 9-char symbolic form AND octal | Only octal parsed → symbolic silently became mode 000 | FIXED (client) | Med | stock vs our client |
| 23 | statx fifo/symlink classification | fifo → `kXR_other` (4); symlink stat follows target | Misclassified fifo / wrong symlink-target flags | FIXED (`test_conf_stattypes.py`) | Med | stock raw-wire (DIFF) |

Latent self-consistency regression worth recording: fix **#7** (4-byte open
reply) desynced the write-through cache's hand-rolled origin client
(`src/cache/origin_protocol.c`), which had over-specified a 12-byte reply,
causing `[3007] write-through flush to origin failed`. Fixed to read only the
4-byte fhandle. This is the canonical class of bug differential conformance work
exposes — a spec-correct wire change breaking an internal peer that
over-specified the old framing. Now guarded by `test_cache_write_through` and the
`test_integrity_matrix` write-through topologies.

### Deferred or by-design — listed honestly

These are **not** fixed. Each states the official behavior, our behavior, status,
and severity. "By-design" means we made a deliberate, defensible choice that
diverges; "deferred" means a known divergence not yet closed.

| Area | Official / reference behavior | Our behavior | Status | Severity |
|---|---|---|---|---|
| POSC disconnect | Stock keeps an un-closed partial pending a reconnect window | We remove the un-closed partial immediately (correct Persist-On-Successful-Close intent) | **By-design** (documented xfail) | Low |
| `mkdir` of a dir it itself created earlier | Stock returns rc=0 idempotently (oss namespace-cache quirk) | We return 3018 for a pre-existing on-disk dir | **By-design** (both valid; pinned by probe) | Low |
| `mkdir` under a file | Stock maps to `ENOTDIR`/3005 | Confined-resolve reports coarser `NotFound`/3011 | **By-design** (both reject; no dir created) | Low |
| Symlink creation via wire | (Stock OSS may create) | We **reject** symlink creation (deliberately stricter; escape-defense posture) | **By-design** (stricter) | Low |
| Login twice on one connection | (Reference tolerance varies) | Accepted | **By-design / deferred** (tolerant) | Low |
| `kXR_ping` before login | (Reference may reject pre-login) | Served | **By-design / deferred** (tolerant) | Low |
| `kXR_pgwrite` info-offset / CSE retransmit | Full corrective-send-error retransmit handshake | Full CSE machine: `pgWrCSE` list, per-handle Fob, `kXR_pgRetry` correction, close gate — byte-exact vs stock | **Parity** | — |
| `kXR_pgread` negative length | Reference-specific handling | Not exhaustively matched | **Deferred** | Low |
| `kXR_prepare` stage request-id format | Specific reqid format | `"0"` in FRM-off legacy mode; durable reqids with `xrootd_frm on` | **By-design** (mode-dependent) | Low |
| `kXR_fattr` List namespace prefix | Specific user-attr namespace prefixing | Maps via local xattrs; prefix nuance may differ | **Deferred** | Low |
| `kXR_query` Qconfig empty-payload | Specific empty-payload form | May differ for empty/edge payloads | **Deferred** | Low |
| `query config fattr` / `query config version` | Returns specific values | Not all config keys reproduced | **Deferred** | Low |
| `kXR_mv` arg1len==0 autosplit | Reference autosplits a single space-joined arg | Not fully matched for the degenerate arg1len==0 form | **Deferred** | Low |
| `kXR_Qopaque`/`Qopaquf`/`Qopaqug` (FSctl) | Plugin-dispatched custom FSctl/FSinfo | Reference-compatible "unsupported" when no plugin; no plugin hooks | **By-design** (no plugin framework) | Low |
| Proxy async `kXR_attn` relay (unsolicited) | Full unsolicited upstream `kXR_attn` dispatch | `kXR_waitresp` forwarded; complete unsolicited-attention path not verified | **Deferred** (serious proxy-mode item) | Med |
| Proxy `kXR_prepare` path-list rewrite | Per-entry path-list rewrite | Whole-payload rewrite flagged in proxy docs | **Deferred** (serious for path-map proxy) | Med |
| Native TPC TLS-upgraded origins / multihop delegation | Broad upstream TPC paths | Basic rendezvous + SHM key registry; TLS-upgrade/multihop/site-credential edges need validation | **Deferred** | Med |
| `kXR_tlsData` / `kXR_tlsSess` independent enforcement | Independently negotiated/enforced | Negotiated but follows login TLS (not independently enforced) | **Deferred** | Low |
| `recoverWrts` semantics | Client honors; server semantics depend on write-recovery support | Per-handle idempotent write replay; review before advertising broadly | **Partial** | Low |
| Client `xrdcp` `--posc` / `-r` (recursive) / `ls` / `--cksum` gaps | Stock client feature breadth | Native client covers core copy/ls/stat/cksum; some flags/recursive modes are narrower | **Deferred** (client-side) | Low |

### Confirmed conformant (no divergence)

For balance: the suites positively confirm streamid echo; `kXR_ping` empty-ok;
pre-login rejection; negative/oversized dlen handling; error-body framing
(`errnum`+NUL, `kXR_NotFound` for ENOENT); handshake reply (`0x520`,
DataServer); `kXR_protocol` flags; 16-byte login sessid; `kXR_stat`
`id size flags mtime`; raw `kXR_read`; `kXR_readv` per-segment framing; and
byte-identical `ls`/`stat`/checksum parity between our server and stock across
`xrdfs` ls/-l/stat/statvfs/locate/query{config,checksum}/mkdir/rmdir/rm/mv/
truncate/chmod/cat/ls-R/tail and `xrdcp` up/download/stdout/1-MiB/`--cksum`, in
both directions (stock client ↔ our server, our client ↔ stock server).

---

## Drop-in replacement assessment by deployment profile

There is no single drop-in answer. The honest per-profile verdict:

| Profile | Verdict | Where it bites |
|---|---|---|
| **Pure POSIX data server** (`root://` + `davs://`, local/parallel-FS storage, GSI/token/SSS/krb5 auth, Prometheus monitoring) | **Strong drop-in candidate.** Full active opcode set through `kXR_clone`, paged I/O, POSC, vector I/O, fattr, confined paths, conformance-tested against stock. | Loses UDP XrdMon (by design); `pwd`/`host` auth absent; complex `XrdAcc` files need translation; no N2N plugin. |
| **Redirector / manager** | **Viable for two/three-tier static + practical CMS** (manager registration, locate, redirect, blacklist, per-server metrics, multi-tier tested). | Full CMS admin socket/tooling, virtual node IDs, and some battle-tested CMS semantics are absent; complex production clusters need explicit conformance testing. |
| **XCache / proxy cache** | **Partial — not a drop-in for PFC-dependent sites.** Read-through/slice cache + eviction + write-through + proxy bridge exist. | No full `XrdPfc` purge/snapshot/policy engine; no `XrdPss` remote-fill-as-storage; proxy unsolicited-`kXR_attn` and per-entry prepare rewrite are deferred. |
| **WebDAV / HTTP(S) gateway** | **Strong, often ahead of upstream.** XrdHttp dialect, range/multipart, HTTP-TPC (hardened), plus `LOCK`/`PROPPATCH`/`SEARCH`/`ACL` beyond upstream's method set. | Native-TPC TLS-upgrade/multihop edges deferred; checksum-plugin breadth limited to the built-in set. |
| **S3 gateway** | **Module-exclusive capability** (no upstream S3 *server*). SigV4, multipart, presigned, POST Object, conditional ops, CRC64NVME. | Path-style focused; virtual-hosted buckets and dynamic STS stores out of scope; S3 SigV4 must never share logic with WLCG tokens (invariant). |
| **Tape / MSS front end** | **Functional gateway, not a drop-in FRM.** Durable stage queue + WLCG Tape REST + `prepare`/`QPrep` (durable reqids with `xrootd_frm on`). | No full `XrdFrm` daemon ecosystem, in-process migrate/purge (scaffold only), MSS driver plugins, or `XrdOssArc`. Validate `prepare`/`cancel`/`evict`/recall against the real storage manager. |
| **EC / Ceph / non-POSIX backend** | **Not a drop-in.** | No `XrdEc`, no `XrdCeph`, no OSS plugin ABI — hard blockers. |
| **`pwd`/`host`-auth or UDP-XrdMon-dependent site** | **Not a drop-in without migration.** | Auth methods and UDP monitoring are absent by design. |

The correct proof point for any of these is never "the feature list says yes" —
it is a site-specific conformance matrix with three tests per critical feature
(success, error, security-negative), per this project's testing rule.

---

## Source references

Official XRootD (`/tmp/xrootd-src/src`):

- Protocol: `XProtocol/XProtocol.hh` (v5.2.0), `XrdXrootd/XrdXrootdProtocol.cc`,
  `XrdXrootd/XrdXrootdXeq.cc`
- Storage/backends: `XrdOss/`, `XrdSfs/`, `XrdEc/`, `XrdCeph/`, `XrdPss/`,
  `XrdPfc/`, `XrdOssCsi/`, `XrdOssArc/`, `XrdZip/`, `XrdRmc/`, `XrdFrc/`
- Tape/FRM: `XrdFrm/`
- Monitoring: `XrdXrootd/XrdXrootdMon*` (UDP f/g-stream)
- Name mapping: `XrdOuc/XrdOucN2NLoader.{cc,hh}`, `XrdOuc/XrdOucN2No2p.cc`
- Shaping: `XrdBwm/`, `XrdThrottle/`
- Diagnostics: `XrdDig/`
- Auth: `XrdSec*/` (`XrdSecgsi`, `XrdSecsss`, `XrdSecunix`, `XrdSeckrb5`,
  `XrdSecpwd`, `XrdSecztn`), `XrdSec/XrdSecProtocolhost.cc`, `XrdAcc/`,
  `XrdMacaroons/`, `XrdSciTokens/`, `XrdVoms/`
- HTTP: `XrdHttp/`, `XrdHttpTpc/`, `XrdHttpCors/`
- Checksums: `XrdCks/`, `XrdVersionPlugin.hh`
- Client: `XrdCl/`, `XrdClS3/` (client S3 plugin), `XrdPosix/`

nginx-xrootd (`src/` and `client/`):

- Protocol/dispatch: `src/protocol/opcodes.h`, `src/protocol/flags.h`,
  `src/handshake/dispatch*.c`, `src/session/protocol.c`, `src/session/signing.c`
- Auth: `src/gsi/`, `src/token/`, `src/sss/`, `src/unix/`, `src/krb5/`,
  `src/voms/`, `src/path/authdb.c`, `src/path/auth_gate.c`
- Storage/cache/path: `src/fs/`, `src/path/`, `src/cache/`,
  `src/compat/namespace_ops.c`, `src/cache/origin_protocol.c`
- FRM/tape: `src/frm/`, `src/query/prepare.c`, `src/webdav/tape_rest.c`
- HTTP/WebDAV/S3: `src/webdav/`, `src/s3/`
- Extras: `src/mirror/`, `src/metrics/`, `src/ratelimit/`, `src/dashboard/`,
  `src/srr/`, `src/pmark/`, `src/compat/codec_*.c`, `src/compat/http_compress.c`
- Client suite: `client/apps/`, `client/lib/`, `client/lib/sigver.c`
- Conformance fixes: `src/read/stat.c`, `src/dirlist/handler.c`,
  `src/path/find_rule.c`, `xrootd_stat_flags_from_stat`,
  `xrootd_reject_dotdot_path`

Consolidated docs: see the six authoritative inputs listed under
[Scope](#scope). Conformance suites:
`tests/test_xrootd_conformance.py`, `tests/test_official_interop.py`,
`tests/test_gohep_interop.py`, `tests/test_conf_*.py`,
`tests/test_conf_stattypes.py`, `tests/test_cache_write_through.py`,
`tests/test_integrity_matrix.py`.
</content>
</invoke>
