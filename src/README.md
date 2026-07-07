# src — nginx-xrootd Source Tree

`nginx-xrootd` turns a stock nginx build into a multi-protocol data gateway for
HEP/grid storage, replacing native XRootD gateway daemons. It speaks the XRootD
binary wire protocol (`root://` / `roots://`) through nginx's **stream** module,
plus WebDAV (`davs://` / `http://`) and an S3-compatible REST subset through
nginx's **HTTP** module. All three protocols project the same on-disk export
root and share one metrics / auth / path-confinement core, so one process can be
deployed as a standalone data server, a CMS cluster member, or a
redirector/manager.

**Deployment thesis:** instead of running separate XRootD, GridFTP, WebDAV, and
S3 daemons in front of a storage volume, run one nginx with this module. You get
the event-loop scalability and TLS/HTTP machinery of nginx, a single
configuration surface, unified Prometheus metrics, and one kernel-confined view
of the export root — across every protocol HEP clients actually use.

The umbrella header [`ngx_brix_module.h`](core/ngx_brix_module.h) wires every
subsystem together; per-connection state lives in `brix_ctx_t`
([types/](core/types/README.md)). Stream entry is
[connection/](protocols/root/connection/README.md) → [handshake/](protocols/root/handshake/README.md); HTTP
entry is [webdav/](protocols/webdav/README.md) and [s3/](protocols/s3/README.md).

---

## Source map

Since phase-66 (2026-07-02) the tree is bucketed by concept — locate any
subsystem from its concept alone:

```
core/           platform primitives (compat, types, config, shm, aio, umbrella header)
protocols/      one subdir per wire protocol: root/ webdav/ s3/ ssi/ srr/ dig/ shared/
fs/             storage plane — the VFS and everything below it (backend, tier, xfer,
                path confinement, cache, scan)
auth/           identity, credentials, authorization (incl. authz/ = ACL + acc engine)
net/            clustering, proxying, traffic shaping/shadowing
observability/  metrics, pmark, dashboard, access logging
tpc/            cross-plane third-party copy
```

Cross-directory includes are **src-rooted** (`#include "auth/gsi/parse.h"`);
same-directory includes stay bare. The full old→new mapping is
[docs/refactor/phase-66-map.tsv](../docs/refactor/phase-66-map.tsv).

Every subsystem below has its own `README.md` (linked) describing its files and
internals. Subsystems are grouped by the layer they belong to.

### Top-level files (now under `core/`)

| File | What it does |
|---|---|
| [core/ngx_brix_module.h](core/ngx_brix_module.h) | Umbrella header that includes every subsystem header and wires the whole module together — the single include that pulls in the full `brix_*` API surface. |
| [core/feature_flags.h](core/feature_flags.h) | Compile-time `BRIX_WITH_*` feature toggles (WebDAV, S3, dashboard, cache, TPC); defaults each to enabled unless the addon config script supplies an explicit `-DBRIX_WITH_*` override to disable it. |

### Entry & dispatch

| Subsystem | What it does |
|---|---|
| [stream](protocols/root/stream/README.md) | nginx `ngx_stream_brix_module` descriptor + the full `brix_*` directive table — the glue that makes a stock nginx aware of the `root://` protocol, installing `ngx_stream_brix_handler`; no protocol logic itself. |
| [connection](protocols/root/connection/README.md) | Stream-side spine for `root://`: per-connection entry point, the byte-framing/async-I/O state machine, response queueing, and the open-file handle table every request passes through. |
| [handshake](protocols/root/handshake/README.md) | XRootD stream entry point: validates the client handshake and routes every opcode through a fixed phase order (sigver verify, security-level enforce, then session/read/write/signing sub-dispatchers) gated by fail-closed login/auth/write checks. |
| [session](protocols/root/session/README.md) | XRootD session lifecycle (protocol/login/auth/bind/ping/endsess/sigver), in-protocol TLS context setup, and the cross-worker SHM session + published-handle registries that let bound secondaries inherit a primary's identity and reopen its files. |
| [webdav](protocols/webdav/README.md) | The HTTP face of the gateway: a WebDAV/HTTPS + WLCG HTTP-TPC + XrdHttp module routing GET/PUT/PROPFIND/COPY/MOVE/LOCK/... through nginx phase handlers, with GSI/token auth, xattr locks, third-party copy, and transparent upstream proxy mode. |
| [s3](protocols/s3/README.md) | nginx HTTP module serving a SigV4-authenticated, S3-compatible REST subset (Get/Head/Put/Delete/List/Copy/multipart/POST-Object) over the same confined export root, in its own auth domain. |

### Protocol handlers

| Subsystem | What it does |
|---|---|
| [read](protocols/root/read/README.md) | Read-half of the wire protocol: file open/close handle lifecycle, `read`/`readv`/`pgread` byte transfer, `stat`/`statx`/`locate` metadata, and `clone` server-side copy — across data-server, manager/redirector, and XCache modes. |
| [write](protocols/root/write/README.md) | Every mutating XRootD stream opcode: `write`/`pgwrite`/`writev`, `sync`/`truncate`, `mkdir`/`rm`/`rmdir`/`mv`/`chmod`, and transactional `chkpoint`, all over the confined local filesystem. |
| [dirlist](protocols/root/dirlist/README.md) | The `kXR_dirlist` operation: enumerates one confined directory and streams entries (optionally with per-entry stat and checksum tokens) as chunked `kXR_oksofar`/`kXR_ok` frames. |
| [fattr](protocols/root/fattr/README.md) | The `kXR_fattr` opcode (Get/Set/Del/List), mapping client extended attributes onto the POSIX `user.U.*` xattr namespace via `getxattr`/`setxattr`/`removexattr`/`listxattr`. |
| [query](protocols/root/query/README.md) | The `kXR_query` sub-protocol dispatcher (checksums, space/fsinfo, config, stats, xattr, opaque/visa stubs) plus the adjacent `kXR_prepare` staging and `kXR_set` advisory-hint opcodes. |

### Data plane

| Subsystem | What it does |
|---|---|
| [aio](core/aio/README.md) | Offloads blocking file I/O (read/readv/pgread/write/pgwrite/writev/dirlist) from the event loop to the thread pool, and owns the shared response-chain builders used identically by the sync and async data paths. |
| [fs](fs/README.md) | The unified VFS layer: one protocol-agnostic `brix_vfs_*` API for all local-filesystem open/read/write/stat/namespace ops, centralizing kernel confinement, metrics, access logging, page-CRC, and cache integration for every front end. |
| [cache](fs/cache/README.md) | XCache-style read-through cache (whole-file and per-slice fills from a remote XRootD origin) plus write-through origin mirroring, with LRU eviction, all origin/disk I/O offloaded to thread-pool workers. |
| [response](protocols/root/response/README.md) | Leaf utility that frames and queues every `root://` wire response — header, `kXR_ok`/error, redirect/wait control hints, `kXR_attn` server-push, and CRC32c-protected `kXR_status` pgread/pgwrite frames — with correct big-endian framing and stream-ID echo. |
| [shared](protocols/shared/README.md) | Cross-protocol helper library: the shared HTTP ranged-file-serving pipeline (used by WebDAV GET and S3 GetObject) and header-only overflow-checked size/array-allocation math for wire-driven allocations. |

### Path & confinement

| Subsystem | What it does |
|---|---|
| [fs/path](fs/path/README.md) | The security boundary between an untrusted client path (`root://` wire, WebDAV URL, or S3 `/<bucket>/<key>`) and any syscall: lexical validation, `openat2` `RESOLVE_BENEATH` confinement, canonicalization/normalization. (Phase-66 split the old `path/` dir: the authdb/VO-ACL/auth-gate/group-policy half now lives in [auth/authz](auth/authz/acc/README.md)'s directory, wire-path extraction in `protocols/root/path/`, and access logging in `observability/accesslog/`.) |

### Authentication

| Subsystem | What it does |
|---|---|
| [gsi](auth/gsi/README.md) | The stream `kXR_auth` credential dispatcher plus the self-contained GSI/x509 two-round DH-over-OpenSSL proxy-certificate authentication (and the in-directory WLCG-JWT `ztn` path). |
| [token](auth/token/README.md) | Validates (and mints) WLCG/SciToken JWT and macaroon bearer tokens — JWKS signature verification, claim/scope parsing, scope-to-path checks, and cross-worker caching — so every protocol shares one fail-closed token-auth core. |
| [krb5](auth/krb5/README.md) | The XRootD `krb5` security protocol for `root://` clients — verifies a client's Kerberos service ticket against the host keytab and maps the principal to a local authenticated identity. |
| [sss](auth/sss/README.md) | XRootD Simple Shared Secret auth — symmetric Blowfish-CFB64, CRC32-integrity, timestamp-replay-windowed identity credentials shared via keytab — for the stream login path, proxy-as-client outbound auth, and CMS cluster peer auth. |
| [unix](auth/unix/README.md) | The XRootD `unix` (client-asserted UNIX-name) scheme: a fail-closed, loopback-by-default handler that validates and trusts a self-declared user/group with no cryptographic proof. |
| [voms](auth/voms/README.md) | Extracts VO membership from VOMS attribute certificates embedded in x509 grid proxies via a runtime-`dlopen`'d `libvomsapi`, producing `primary_vo`/`vo_list` strings that drive `brix_require_vo` ACLs. |
| [crypto](auth/crypto/README.md) | Shared OpenSSL X.509/PKI core: builds CA+CRL trust stores, verifies proxy-cert chains, runs the startup CA/CRL consistency audit, and does OCSP revocation/stapling for both the stream GSI and WebDAV/DAVS cert-auth paths. |

### Cluster & federation

| Subsystem | What it does |
|---|---|
| [manager](net/manager/README.md) | The cluster/redirector control plane: SHM server registry, redirect-collapse cache, pending-locate correlation table, and active health checks that let the gateway pick and redirect clients to the best data server. |
| [cms](net/cms/README.md) | Speaks the XRootD CMS cluster-control protocol both ways — a per-worker heartbeat client that announces this node up to a manager, and a manager-side server module that accepts/registers data nodes — to form a redirector mesh. |
| [upstream](net/upstream/README.md) | A fully non-blocking outbound XRootD client used in manager/redirector mode: connects to a backend data server (bootstrap → optional TLS → login → optional ztn auth), relays one saved `kXR_locate`/`open`/`stat` opcode, and translates the reply back to the original client. |
| [proxy](net/proxy/README.md) | A transparent reverse proxy that authenticates `root://` clients locally and relays every post-login opcode verbatim to a remote upstream XRootD server, with file-handle translation, lazy-open/`kXR_wait`/`kXR_redirect` transparency, splice zero-copy, credential-scoped connection pooling, and audit/metrics. |
| [tpc](tpc/README.md) | Native XRootD third-party copy: the destination gateway opens an outbound XRootD client connection, pulls a remote file into the confined local export off the event loop, and coordinates source-side rendezvous via an SHM key registry. |
| [tpc/common](tpc/common/README.md) | Protocol-neutral TPC support core — shared authorization, credential parsing, a cross-process SHM transfer registry, and unified metrics — used identically by both the native XRootD pull and WebDAV COPY transports. |

### Cross-cutting

| Subsystem | What it does |
|---|---|
| [config](core/config/README.md) | nginx config plumbing for the stream module — directive setters, create/merge srv-conf callbacks, fail-fast startup validation, SHM-zone + thread-pool creation, per-worker resource init (confinement rootfd, timers, crypto pools), and the shared config preamble reused by WebDAV/S3. |
| [types](core/types/README.md) | The module's shared type vocabulary: per-connection context (`brix_ctx_t`), per-server config (`ngx_stream_brix_srv_conf_t`), per-open-file slot (`brix_file_t`), the state-machine enum, compile-time tunables/metric macros, and the canonical protocol-agnostic authenticated principal (`brix_identity_t`). |
| [protocol](protocols/root/protocol/README.md) | Header-only single source of truth for the `root://` binary wire protocol: opcodes, status/error codes, option bitmasks, and packed on-wire request/response structs mirrored from `XProtocol.hh`. |
| [compat](core/compat/README.md) | Protocol-neutral shared primitives (CRC32c/checksums, HTTP request/response & range/XML helpers, kernel-confined filesystem mutations, atomic staged writes, SSRF guard, errno→status mapping) reused by all protocol paths so behavior never diverges. |
| [shm](core/shm/README.md) | A generic open-addressed key/value hash table in nginx shared memory (`kv.*`) plus a thin token-bucket rate limiter (`rate_limit.*`) built on it — the substrate for the JWT/token cache, auth-result cache, and request throttling. |
| [metrics](observability/metrics/README.md) | Single SHM counter store plus the two-module split (stream writers + HTTP `/metrics` exporter) that emits all observability in Prometheus text format. |
| [dashboard](observability/dashboard/README.md) | A dual-context (stream-producer / HTTP-consumer) live transfer monitor exposing transfers, events, history, cache, and cluster state via an HTTPS page + JSON API over three SHM zones, plus a fail-closed REST admin write API for cluster/proxy-pool mutations. |
| [srr](protocols/srr/README.md) | WLCG Storage Resource Reporting endpoint — serves the `storageservice` JSON document (per-share total/used space from `statvfs(2)` + protocol-endpoint metadata) over HTTP for WLCG accounting tooling (CRIC, space-accounting harvester), as an HTTP/JSON-native alternative to the XRootD UDP f-stream/g-stream monitoring stack. |
| [ratelimit](net/ratelimit/README.md) | Identity-aware (VO/issuer/IP/DN/volume) leaky-bucket limiter enforcing request-rate, bandwidth, and concurrency caps over SHM slab zones — throttling `root://` clients with `kXR_wait` and HTTP/WebDAV clients with 429 + Retry-After. |
| [pmark](observability/pmark/README.md) | SciTags network packet marking — tags each data flow with an `(experiment, activity)` pair via out-of-band firefly UDP reports + in-band IPv6 flow-label stamping, compatible with XRootD's `pmark`/SciTags collectors; shared across root://, WebDAV, and S3. |
| [mirror](net/mirror/README.md) | Fire-and-forget traffic mirroring that replays sampled XRootD-stream and WebDAV/HTTP requests to shadow backends after the primary is answered, comparing status and counting divergence without ever delaying or exposing the shadow path to the client. |

### WebDAV sub-helpers

These live under [webdav/](protocols/webdav/README.md) and back its method handlers.

| Subsystem | What it does |
|---|---|
| [webdav/fs](protocols/webdav/fs/README.md) | Confined local-filesystem copy primitives (file + recursive directory) backing the WebDAV COPY/MOVE handler, with kernel zero-copy and XRootD/WebDAV xattr preservation. |
| [webdav/locks](protocols/webdav/locks/README.md) | Request-parsing helpers that decode WebDAV LOCK intent (Timeout, If/Lock-Token, Depth, owner/scope) from the HTTP request for the lock state machine in `../lock.c`. |
| [webdav/methods](protocols/webdav/methods/README.md) | A thin per-method helper layer holding the COPY destination conditional check (If-Match/If-None-Match), delegating ETag parsing to the shared compat layer for RFC 9110 optimistic-concurrency safety. |
| [webdav/util](protocols/webdav/util/README.md) | Thin protocol-aware adapters that wrap the all-protocol compat URI-decode and XML-escape primitives into nginx-HTTP dialect (nginx status codes + request-pool allocation) for WebDAV handlers. |

---

## The four request lifecycles

> **Visual call-ladders:** [`docs/11-architecture/request-lifecycle-sequences.md`](../docs/11-architecture/request-lifecycle-sequences.md)
> renders each of the four flows below as a step-by-step sequence diagram annotated with the
> real `function() (file.c:line)` at every hop — the fastest way to trace a request end-to-end.

### `root://` stream

1. **[connection](protocols/root/connection/README.md)** — TCP accept → `ngx_stream_brix_handler` allocates `brix_ctx_t`, marks fd slots free, generates a session ID; `recv` accumulates the request header.
2. **[handshake](protocols/root/handshake/README.md)** — `brix_dispatch()` runs sigver checks, then security-level enforcement.
3. **[session](protocols/root/session/README.md)** + **[gsi](auth/gsi/README.md)**/[token](auth/token/README.md)/[krb5](auth/krb5/README.md)/[sss](auth/sss/README.md)/[unix](auth/unix/README.md)/[voms](auth/voms/README.md) — `dispatch_session` handles login/auth.
4. **[proxy](net/proxy/README.md)** / **[manager](net/manager/README.md)** — if proxy or manager mode, the request is forwarded or redirected here; otherwise continue.
5. **[ratelimit](net/ratelimit/README.md)** — request-rate / concurrency gate.
6. **[read](protocols/root/read/README.md)** / **[write](protocols/root/write/README.md)** / [dirlist](protocols/root/dirlist/README.md) / [query](protocols/root/query/README.md) / [fattr](protocols/root/fattr/README.md) — the opcode handler runs.
7. **[path](fs/path/README.md)** — the client path is resolved beneath the export root before any syscall.
8. **[fs](fs/README.md)** + **[aio](core/aio/README.md)** ([cache](fs/cache/README.md) if enabled) — I/O is offloaded to the thread pool.
9. **[response](protocols/root/response/README.md)** + **[metrics](observability/metrics/README.md)** — the reply is framed and counters updated.

### `davs://` WebDAV

1. **[webdav](protocols/webdav/README.md)** access phase — auth (cert via [crypto](auth/crypto/README.md), bearer via [token](auth/token/README.md)), CORS, write-allow, and scope checks.
2. **[webdav](protocols/webdav/README.md)** `dispatch.c` content handler — routes by HTTP method.
3. **[path](fs/path/README.md)** — `resolve_path()` confines the path; `webdav_check_locks()` ([webdav/locks](protocols/webdav/locks/README.md)) checks the lock store.
4. **Method handler** — GET serves a ranged file via [shared](protocols/shared/README.md); PUT reads the body async via [aio](core/aio/README.md)/[fs](fs/README.md); COPY/MOVE use [webdav/fs](protocols/webdav/fs/README.md) locally or, with `Source:`/`Credential:` headers, drive HTTP-TPC via [tpc/common](tpc/common/README.md); URI/XML helpers come from [webdav/util](protocols/webdav/util/README.md) and conditional checks from [webdav/methods](protocols/webdav/methods/README.md).
5. **[metrics](observability/metrics/README.md)** — `webdav_metrics_return` records bytes/status.

### S3 REST

1. **[s3](protocols/s3/README.md)** — `ngx_http_s3_handler` parses `/<bucket>/<key>`.
2. **[s3](protocols/s3/README.md)** auth — SigV4 verification, fail-fast (a distinct auth domain from WLCG tokens).
3. **[path](fs/path/README.md)** — `s3_resolve_key()` confines the key under the export root.
4. **Method/query dispatch** — ListObjectsV2 / GetObject (via [shared](protocols/shared/README.md)) / PutObject / multipart / CopyObject; writes gated on `allow_write` before the body is read.
5. **[fs](fs/README.md)** + **[aio](core/aio/README.md)** + **[metrics](observability/metrics/README.md)** — I/O and counters.

### CMS cluster redirect

1. **[cms](net/cms/README.md)** client — data servers run the per-worker heartbeat client: login + periodic load/space frames to the manager.
2. **[manager](net/manager/README.md)** registry — the manager records each node in its SHM server registry.
3. **[read](protocols/root/read/README.md)** (`kXR_locate`/`kXR_open`) in manager mode — `brix_srv_select()` picks the best server (falling back to an [upstream](net/upstream/README.md) query on a miss).
4. **[response](protocols/root/response/README.md)** — replies `kXR_redirect`.
5. **[manager](net/manager/README.md)** redir_cache — the choice is cached (TTL) to skip repeat CMS round-trips.

---

## Cross-cutting invariants

Read these before changing any wire/client path — they are enforced project-wide.

1. **Kernel confinement is mandatory.** Every wire/client path goes through
   [path/](fs/path/README.md) (`openat2` + `RESOLVE_BENEATH` against a per-worker
   `O_PATH` rootfd) before any syscall. `EXDEV` = escape attempt → map to
   `kXR_NotAuthorized` / 403. Never call a raw `open`/`stat` on a client path.
2. **TLS vs cleartext buffers never mix.** TLS responses are memory-backed
   (`b->memory = 1`); cleartext uses file-backed buffers + sendfile. pgread/pgwrite
   require `kXR_status` (4007) framing with per-page CRC32c (see
   [response/](protocols/root/response/README.md)).
3. **Event loop, no blocking.** All blocking file I/O detours through
   [aio/](core/aio/README.md) (the `_thread` step runs `pread`/`pwrite`; the `_done`
   step fires on the single-threaded event loop and rebuilds the response chain
   identically to the sync path). No sleep/blocking read in handlers; use timers.
4. **nginx allocation discipline.** HTTP: `ngx_palloc(r->pool, …)`; stream:
   `ngx_alloc(…, log)`; never raw `malloc`. `ngx_str_t` is **not** NUL-terminated —
   use `.len`/`ngx_memcpy`, never `strcpy`/`strlen`.
5. **Fail-closed auth.** `allow_write` is checked globally before token scope; auth
   gates grant access only on explicit `NGX_OK`. S3 SigV4 and WLCG tokens are
   distinct auth domains and never share logic. Metric labels stay low-cardinality
   (no paths/buckets/UUIDs/DNs).

---

## How to navigate / where to start reading

- **Big picture first:** read this file, then [ngx_brix_module.h](core/ngx_brix_module.h)
  (the umbrella header that includes every subsystem) and [types/](core/types/README.md)
  (the `brix_ctx_t` per-connection context that threads through everything).
- **Follow a `root://` request:** start at [connection/](protocols/root/connection/README.md) →
  [handshake/](protocols/root/handshake/README.md) → [session/](protocols/root/session/README.md) →
  [read/](protocols/root/read/README.md) or [write/](protocols/root/write/README.md).
- **Follow an HTTP request:** start at [webdav/](protocols/webdav/README.md) (or
  [s3/](protocols/s3/README.md)) → [path/](fs/path/README.md) → method handler →
  [fs/](fs/README.md).
- **Understand the wire format:** [protocol/](protocols/root/protocol/README.md) is the
  header-only spec; [response/](protocols/root/response/README.md) shows how frames are built.
- **Touching security:** read the **Cross-cutting invariants** above, then
  [path/](fs/path/README.md) and the relevant auth subsystem
  ([gsi/](auth/gsi/README.md), [token/](auth/token/README.md), [crypto/](auth/crypto/README.md)).
- Every folder has its own `README.md` with a per-file map — open the subsystem's
  README before reading its `.c` files.
