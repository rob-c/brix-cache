# Forward vs Reverse Proxying in nginx-xrootd

This document defines the two classical proxy models — **forward** and
**reverse** — plus the two hybrid shapes this codebase actually implements
(**transparent relay** and **caching reverse proxy**), and maps every
proxy-flavoured feature in the tree onto one of them. Each feature section
includes an ASCII data-flow diagram showing the client, the proxy (this
nginx-xrootd node), and the origin/source.

Related reading: [deployment-modes.md](deployment-modes.md),
[`src/net/proxy/README.md`](../../src/net/proxy/README.md),
[`src/fs/cache/origin/README.md`](../../src/fs/cache/origin/README.md),
[`src/net/mirror/README.md`](../../src/net/mirror/README.md).

---

## 1. The two classical models

The distinction is **not** about where the box sits on the network. It is
about **who chooses the destination** and **on whose behalf the proxy acts**:

| Question | Forward proxy | Reverse proxy |
|---|---|---|
| Who names the origin? | The **client** (in the request itself) | The **operator** (in the proxy's config) |
| Who does the proxy represent? | The client (it acts *outward* on the client's behalf) | The origin (it acts *inward* on the server's behalf) |
| Who is hidden from whom? | The client is hidden from the origin | The origin is hidden from the client |
| What does the client configure? | A proxy setting (`http_proxy=…`, `CVMFS_HTTP_PROXY=…`) | Nothing — it just connects to the advertised endpoint |
| Typical request shape (HTTP) | `GET http://origin.example/path HTTP/1.1` (**absolute-URI**) | `GET /path HTTP/1.1` (origin-form, `Host:` names the proxy) |
| Trust model | Proxy must **constrain** which origins clients may reach (allowlist), or it is an *open proxy* | Proxy must **authenticate clients** at the perimeter; origins are fixed and trusted |
| Classic example | Squid site proxy | nginx in front of an app server |

### 1.1 Forward proxy — data flow

The client explicitly addresses the proxy and *tells it* where to go. The
origin sees the proxy's address, not the client's.

```
             client picks the origin; proxy just carries it there
             (client is configured with proxy=P, request names O)

  ┌────────┐  1. GET http://ORIGIN/path   ┌───────────┐  2. GET /path      ┌────────┐
  │ CLIENT │ ───────────────────────────▶ │  FORWARD  │ ─────────────────▶ │ ORIGIN │
  │        │      (absolute-URI,          │  PROXY P  │   (proxy connects  │   O    │
  │        │       sent TO the proxy)     │           │    outward to O)   │        │
  │        │ ◀─────────────────────────── │           │ ◀───────────────── │        │
  └────────┘  4. response (maybe cached)  └───────────┘  3. response       └────────┘

  Origin O only ever sees proxy P's source address.
  P MUST allowlist which origins it will dial, or it is an open relay.
```

### 1.2 Reverse proxy — data flow

The client thinks the proxy **is** the server. The proxy's config — not the
request — decides which backend receives the traffic.

```
             operator picks the origin; client never learns it exists

  ┌────────┐  1. GET /path                ┌───────────┐  2. GET /path      ┌─────────┐
  │ CLIENT │ ───────────────────────────▶ │  REVERSE  │ ─────────────────▶ │ BACKEND │
  │        │   (client believes P IS      │  PROXY P  │  (backend chosen   │ /ORIGIN │
  │        │    the storage endpoint)     │           │   from P's config: │         │
  │        │ ◀─────────────────────────── │           │   upstream list,   │         │
  └────────┘  4. response                 └───────────┘   health, rr, …)   └─────────┘
                                                        ◀───────────────── 3. response

  Client only ever sees proxy P. Auth is (usually) TERMINATED at P:
  P verifies the client (TLS / token / GSI), then talks to the backend
  with its own (or forwarded, or no) credentials.
```

### 1.3 The two hybrid shapes this codebase adds

**Transparent relay** (a *non-terminating* reverse proxy): topologically a
reverse proxy — the operator picks the upstream — but the proxy terminates
**nothing**. TLS/GSI/token handshakes travel end-to-end between client and
backend; the relay pumps bytes verbatim and can only *observe* what happens
to be cleartext. It holds no credential and can alter no frame.

```
  ┌────────┐   bytes (verbatim, incl.    ┌───────────┐   bytes (verbatim)  ┌─────────┐
  │ CLIENT │ ◀═════════════════════════▶ │TRANSPARENT│ ◀═════════════════▶ │ BACKEND │
  │        │   auth handshake, TLS,      │   RELAY   │                     │         │
  └────────┘   everything)               └─────┬─────┘                     └─────────┘
                                               │ passive tap (read-only copy
                                               ▼ of whatever is cleartext)
                                         ┌───────────┐
                                         │ audit log │
                                         └───────────┘
```

**Caching reverse proxy** (read-through cache): a reverse proxy that keeps a
local copy. On a miss the proxy acts *as a client* toward the origin, stages
the bytes locally, then serves this and every future request from local
storage. Squid-in-accelerator-mode, Varnish, and XCache are all this shape.

```
        HIT path:                          MISS (fill) path:

  ┌────────┐  GET /f   ┌───────┐     ┌────────┐  GET /f   ┌───────┐  ranged GET /f  ┌────────┐
  │ CLIENT │ ────────▶ │ CACHE │     │ CLIENT │ ────────▶ │ CACHE │ ──────────────▶ │ ORIGIN │
  │        │ ◀──────── │ node  │     │        │           │ node  │ ◀────────────── │        │
  └────────┘  bytes    └───┬───┘     └────────┘           └───┬───┘  bytes → .part  └────────┘
                           │                                  │  verify checksum,
                     local store                              │  atomically publish,
                     (no origin                               ▼  then serve locally
                      contact at all)                    local store
```

---

## 2. Feature → model map (the short answer)

| Feature | Directive(s) | Model | Auth terminated here? | Origin chosen by | Code |
|---|---|---|---|---|---|
| Terminating root:// proxy ("tap proxy") | `xrootd_tap_proxy`, `xrootd_tap_proxy_upstream`, `_auth`, `_login_user`, `_audit_log`, `_upstream_tls` | **Reverse** (terminating) | **Yes** (token/GSI/SSS/anon) | Operator config (upstream list, rr + health) | `src/net/proxy/` |
| Transparent root:// relay + tap | `xrootd_transparent_proxy host:port` | **Transparent relay** (reverse topology, nothing terminated) | **No** — auth travels end-to-end | Operator config (single target) | `src/protocols/root/relay/`, `src/net/tap/` |
| Single-port HTTP handoff | `xrootd_http_handoff host:port` | **Transparent relay** (local mux) | No (the WebDAV listener it splices to does its own auth) | Operator config (local WebDAV port) | `src/protocols/root/handoff/` |
| WebDAV perimeter proxy | `webdav_proxy_handler` machinery (directives currently disabled; `xrootd_webdav_proxy_certs` that remains is GSI *auth*, not proxying) | **Reverse** (terminating, HTTP) | **Yes** (TLS + WLCG token / GSI) | Operator config (static/dynamic backend pool) | `src/protocols/webdav/proxy*.c` |
| Read-through cache (all protocols) | `xrootd_storage_backend <origin-url>` + `xrootd_cache_store <dir>` (and the `xrootd_webdav_*`/`xrootd_s3_*`/`xrootd_cvmfs_*` per-protocol spellings) | **Caching reverse proxy** | **Yes** (normal protocol auth) | Operator config (origin URL; root://, http(s)://, pelican://, S3) | `src/fs/cache/`, `src/fs/cache/origin/`, `src/fs/backend/xroot/` |
| CVMFS site cache — reverse mode | `xrootd_cvmfs on` + `xrootd_cvmfs_storage_backend http://stratum1/cvmfs/<repo>` + `xrootd_cvmfs_cache_store` | **Caching reverse proxy** | N/A (CVMFS data is content-addressed + signed; anonymous GET) | Operator config (Stratum-1 set, failover) | `src/protocols/cvmfs/` |
| CVMFS site cache — proxy mode (T14) | absolute-URI listener + `xrootd_cvmfs_upstream_allow`, `xrootd_cvmfs_upstream_max` | **FORWARD proxy** (allowlisted) — the only one in the tree | N/A (same CVMFS trust model) | **Client** (`CVMFS_HTTP_PROXY` absolute-URI), constrained by the allowlist | `src/protocols/cvmfs/` (phase-68 T14; ctx plumbing landed, request/upstream registry in progress) |
| Traffic mirroring / shadow replay | `xrootd_mirror_url`, `xrootd_stream_mirror_url`, `xrootd_mirror_*` | **Reverse-shaped fan-out**, out-of-band (fire-and-forget; client never sees the shadow) | Primary request's auth applies; credentials stripped/replaced toward the shadow | Operator config (≤4 shadow targets) | `src/net/mirror/` |
| Third-party copy (TPC) | root:// native TPC, WebDAV `COPY` + `Source:`/`TransferHeader*` | **Forward-flavoured fetch** (server acts as a client toward a *client-named* source) | Yes (the TPC request itself) | **Client** (names the remote source/destination URL in the request) | `src/tpc/`, `src/protocols/webdav/tpc*.c` |
| CMS redirection | `xrootd_cms_*` (manager/redirector role) | **Neither** — a redirect, not a proxy: data bypasses the manager entirely | Yes (login), but no data flows through | Manager picks a data server, tells the client to go there | `src/net/cms/`, `src/net/manager/` |
| Protocol tap | (library — fed by the two root:// proxy modes) | Not a proxy — a passive observation layer | — | — | `src/net/tap/` |

---

## 3. Feature details and data-flow diagrams

### 3.1 Terminating root:// reverse proxy — `xrootd_tap_proxy`

`src/net/proxy/` (README still titles it `xrootd_proxy`; the live directive
surface is `xrootd_tap_proxy*` in `src/protocols/root/stream/module.c`).

A full **terminating reverse proxy** for the binary XRootD wire protocol.
nginx authenticates the client itself (token / GSI / SSS / anonymous),
terminates client-side TLS, then forwards every post-login opcode to a
configured upstream XRootD server over its **own** upstream session
(handshake → `kXR_protocol` → `kXR_login` → optional `kXR_auth`). The
backend is invisible: file handles are translated end-to-end, responses are
relayed under the client's own streamid, `kXR_wait` is absorbed and retried,
`kXR_redirect` is followed (≤3 hops) *by the proxy*, and plaintext
`kXR_read`/`kXR_pgread` bodies take a zero-copy `splice()` fast path.
Upstream connections come from a worker-local pool keyed by (upstream, auth
type, token hash), with per-upstream health tracking and round-robin across
healthy endpoints. Because the proxy sees full plaintext on both legs, the
`src/net/tap/` decoder is wired into both directions and every file/path op
lands in a JSON audit log.

```
                 CLIENT LEG                              UPSTREAM LEG
        (terminated: OUR auth, OUR TLS)        (proxy's OWN session + credentials)

  ┌────────┐ handshake+login+auth ┌──────────────────┐ handshake+login(+ztn/sss) ┌──────────┐
  │ xrdcp/ │ ◀──────────────────▶ │   nginx-xrootd   │ ◀───────────────────────▶ │ upstream │
  │ XrdCl  │                      │  xrootd_tap_proxy│                           │  xrootd  │
  │ client │  kXR_open /f ──────▶ │                  │ ──▶ kXR_open /pfx/f       │  server  │
  │        │                      │  fh 0 ⇆ fh 7     │      (path rewritten)     │          │
  │        │ ◀── ok, fh=0         │  (handle map)    │ ◀── ok, fh=7              │          │
  │        │  kXR_read fh=0 ────▶ │                  │ ──▶ kXR_read fh=7         │          │
  │        │ ◀══ data ═══════════ │ ◀═══ splice() ═══│ ◀══ data ════════════════ │          │
  └────────┘   (client streamid)  └───────┬──────────┘   (zero-copy plaintext)   └──────────┘
                                          │ tap: decode C2U + U2C frames
                                          ▼
                                   JSON audit log (opcodes, paths, users,
                                   handles, path-mutation ops, close stats)

  WHY reverse: the client never names the upstream; xrootd_tap_proxy_upstream
  entries + health + round-robin decide. kXR_redirect from the backend is
  FOLLOWED here, not relayed — the backend topology stays hidden.
```

Upstream credentialing (`xrootd_tap_proxy_auth`): anonymous login, forward
the client's WLCG bearer as a `ztn` credential, SSS keys (global or
per-upstream), file-based token bridge, or GSI delegation
(`gsi_upstream*.c`, threaded blocking login with a delegated proxy cert).

### 3.2 Transparent root:// relay + tap — `xrootd_transparent_proxy`

`src/protocols/root/relay/` + `src/net/tap/tap_stream.c`.

The **non-terminating** counterpart of §3.1. Every connection accepted on
the port is relayed **verbatim** to one configured upstream XRootD server
before any XRootD frame is parsed. The client's auth handshake — anonymous,
token, x509, full GSI — travels end-to-end; the relay holds **no**
credential and cannot alter a byte. In parallel, a per-direction streaming
decoder (`xrootd_tap_stream`) is fed each freshly-received chunk and emits
whatever is cleartext (opcodes, paths, handles, status codes) to a JSON
audit log. The client→upstream side skips the 20-byte handshake preamble
before frame decode.

```
  ┌────────┐                        ┌──────────────────┐                        ┌──────────┐
  │ CLIENT │ ◀═════ ALL bytes ════▶ │   nginx-xrootd   │ ◀═════ ALL bytes ════▶ │ upstream │
  │        │   verbatim, both       │ transparent relay│    verbatim, both      │  xrootd  │
  │        │   directions: hello,   │  (buffered TCP   │    directions          │  server  │
  │        │   kXR_login, GSI/TLS   │   pump, no frame │                        │          │
  │        │   handshake, data      │   termination)   │                        │          │
  └────────┘                        └───────┬──────────┘                        └──────────┘
              GSI / token / x509 auth ══════│═══════════▶ verified BY THE UPSTREAM,
              (end-to-end — relay never     │             not by the relay
               sees a decrypted secret)     │
                                            ▼ non-consuming tap per direction
                                     ┌─────────────┐
                                     │ JSON audit  │  only what travels in
                                     │    log      │  CLEARTEXT is decodable
                                     └─────────────┘

  Trade-off vs §3.1: zero credential exposure and perfect wire fidelity,
  but no handle translation, no redirect following, no path rewriting,
  and blindness to anything the client encrypts.
```

### 3.3 Single-port HTTP handoff — `xrootd_http_handoff`

`src/protocols/root/handoff/`. A **local transparent relay** used as a
protocol multiplexer, not an off-box proxy. Stock XRootD multiplexes HTTP
(XrdHttp) on its data port, so a stock redirector sends HTTP clients to a
data server's *data* port. nginx serves WebDAV on a separate `http{}` port —
so an nginx data node behind a stock redirector would be unreachable over
WebDAV. The stream listener sniffs the first bytes: an XRootD hello always
begins with a zero streamid word, so an HTTP method letter or a TLS
ClientHello (`0x16`) is unambiguously not XRootD. Non-XRootD connections are
spliced (already-read prefix replayed first) to the node's own WebDAV
listener.

```
                          one advertised port (e.g. 1094)
  ┌────────────┐  first bytes?   ┌────────────────────────────┐
  │ any client │ ──────────────▶ │  nginx-xrootd stream port  │
  └────────────┘                 │                            │
                                 │  0x00 streamid word        │──▶ normal root:// path
   root:// hello ───────────────▶│  (XRootD hello)            │    (local handlers / §3.1 / §3.2)
                                 │                            │
   "GET /…" or TLS 0x16 ────────▶│  anything else + handoff   │──▶ raw byte relay to
                                 │  configured                │    LOCAL WebDAV listener
                                 └────────────────────────────┘    (prefix bytes replayed,
                                                                    then verbatim pump)
                                        │
                                        ▼
                               ┌─────────────────┐
                               │ local http{}    │  does its OWN TLS + auth;
                               │ WebDAV listener │  the handoff terminates nothing
                               └─────────────────┘
```

Reverse-proxy topology (the client didn't ask for the WebDAV port), but like
§3.2 it terminates nothing itself — the target listener owns auth.

### 3.4 WebDAV perimeter reverse proxy

`src/protocols/webdav/proxy*.c` (Mode 3, "WebDAV Perimeter Proxy").
**Status:** the machinery (`webdav_proxy_handler`, backend pools, health) is
in the tree, but the enabling directives were removed from the live command
table in 2026-06 — the `xrootd_webdav_proxy_certs` directive that remains
configures GSI client-cert *authentication*, not proxying.

A classic HTTP **terminating reverse proxy** built on nginx's native
upstream API: nginx terminates client HTTPS + WLCG token auth at the
perimeter, then relays the WebDAV operation to an internal backend, with
three credential policies toward the backend — `anonymous` (strip
`Authorization`; internal-trust), `forward` (pass the client's header
unchanged), `token` (replace with a static site service-account bearer).
Backends come from a config-time pool or a dynamic SHM pool with
runtime add/remove/drain.

```
  ┌────────┐  HTTPS + Bearer <wlcg-token>  ┌──────────────────┐   plain HTTP (or https)  ┌──────────┐
  │ davs://│ ────────────────────────────▶ │   nginx-xrootd   │ ───────────────────────▶ │ internal │
  │ client │   TLS + token TERMINATED ──▶  │  perimeter proxy │   auth policy:           │ DAV/     │
  │        │   here (perimeter)            │                  │   anonymous│forward│token │ XrdHttp  │
  │        │ ◀──────────────────────────── │  backend pool    │ ◀─────────────────────── │ backend  │
  └────────┘   response                    │  (static/SHM,    │   response               └──────────┘
                                           │   health, pick)  │
                                           └──────────────────┘
  WHY: one TLS/token termination point for a whole farm of plain-HTTP
  DAV backends — no per-backend certificates or token validation.
```

### 3.5 Read-through cache — the caching reverse proxy

`src/fs/cache/` (fill engine, cinfo state, eviction, write-through) +
`src/fs/cache/origin/` (pluggable origin transports) +
`src/fs/backend/xroot/` (root:// origin as a storage driver). Configured by
composing `xrootd_storage_backend <origin-url>` (where the bytes come from)
with `xrootd_cache_store <dir>` (where they land) — per-protocol spellings
`xrootd_webdav_*`, `xrootd_s3_*`, `xrootd_cvmfs_*` exist over the same
shared tier struct.

This is the shape XCache / Squid-accelerator / Varnish occupy: a **reverse
proxy that owns local storage**. The client speaks any front protocol
(root://, WebDAV, S3, cvmfs://) to this node; on a miss the node acts *as a
client* toward the operator-configured origin — over the XRootD wire
protocol, HTTP(S) (libcurl, ranged GET + `Want-Digest`), or a Pelican
federation (director discovery + 307-following; the node can also
*advertise itself* to the director via `pelican_register.c`). Fills run in a
thread pool, stage into a `.part` file, verify the origin's advertised
checksum, and atomically publish; concurrent requests for the same object
coalesce onto one fill.

```
                       FRONT (reverse-proxy face)                    BACK (client face)

  ┌────────┐  root:// / davs:// / s3 / cvmfs  ┌──────────────────┐
  │ CLIENT │ ───────────────────────────────▶ │   nginx-xrootd   │
  │        │      normal protocol auth        │    cache node    │
  └────────┘                                  │                  │
                                              │  present-bitmap  │   MISS: ranged fetch as a client
                        HIT ◀─── local store ─┤  (.cinfo) lookup ├─────────────────────────────────┐
                                              └──────────────────┘                                 │
                                                                                                   ▼
        ┌──────────────────────────────────────────────────────────────────────────────────┐
        │  origin transports (operator-configured URL decides the driver):                  │
        │    root://origin:1094/   → native async XRootD client (origin_protocol.c / io.c)  │
        │    http(s)://origin/     → libcurl ranged GET, Digest capture (http_transport.c)  │
        │    pelican://federation/ → director discovery → 307 → HTTP GET     (pelican.c)    │
        │  fill: origin ──▶ .part fd ──▶ checksum verify ──▶ atomic publish ──▶ serve       │
        └──────────────────────────────────────────────────────────────────────────────────┘

  Reverse because: the client NEVER names the origin — xrootd_storage_backend
  does. The cache may even hide the origin's existence entirely (pure cache
  node: xrootd_root optional, namespace served from the cache).
```

### 3.6 CVMFS site cache — reverse mode (`cvmfs://` protocol plane)

`src/protocols/cvmfs/` (phase-68). CVMFS is a natural caching workload: all
data objects are **content-addressed** (`/data/<2hex>/<38hex>` — immutable,
cacheable forever) and the mutable metadata (`.cvmfspublished` manifest,
whitelist, reflog) is **signed by the repository**, so the cache needs no
client auth to be safe — but it must not become a generic open endpoint.

In **reverse mode** (implemented) the node is a drop-in Squid/Varnish
replacement for a Tier-2 site: the CVMFS clients' `CVMFS_SERVER_URL` points
at this node, and `xrootd_cvmfs_storage_backend http://stratum1/cvmfs/<repo>`
names the Stratum-1 set. A dedicated content handler (never the WebDAV
dispatch) gates every request: GET/HEAD only, a pure-C URL classifier
accepts exactly the CVMFS traffic shapes and 403s everything else (one
stable `cvmfs-reject:` WARN line that httpguard/fail2ban key on), the geo
API and (until T12) manifests are relayed uncached, and CAS objects fall
through to the shared cache tier (open-or-fill, coalescing, verify-on-fill
against the hash *in the URL*).

```
  ┌────────────┐  GET /cvmfs/repo/data/ab/cdef…   ┌──────────────────────┐
  │ CVMFS      │ ───────────────────────────────▶ │  nginx-xrootd cvmfs  │
  │ client     │    (origin-form URI — client     │  ┌────────────────┐  │
  │ (site      │     was pointed at this node     │  │ gate/classify: │  │
  │  worker    │     as its "server")             │  │ CAS│MANIFEST│  │  │
  │  node)     │                                  │  │ GEO│REJECT(403)│ │
  └────────────┘                                  │  └───┬────────┬───┘  │
        ▲                                         │  CAS │        │ GEO/ │
        │                                         │      ▼        ▼ MANIFEST
        │            HIT: local CAS store ◀───────┤  cache tier   uncached
        │                                         │  (verify hash  passthrough
        │                                         │   from URL     │
        └── bytes ────────────────────────────────┤   on fill)     │
                                                  └──────┬─────────┼──────┘
                                                    MISS │         │
                                                         ▼         ▼
                                                  ┌────────────────────┐
                                                  │ Stratum-1 set      │  operator-configured,
                                                  │ (failover/geo/rtt  │  failover per upstream
                                                  │  selection)        │  outcome — never-drop
                                                  └────────────────────┘  client semantics
```

### 3.7 CVMFS site cache — proxy mode (T14): the one true FORWARD proxy

Phase-68 Task 14 (**in progress** — the per-request `sd_override` /
upstream-registry plumbing is in `cvmfs.h`/`handler.c`; the absolute-URI
request parser and lazy per-upstream backend registry land with T14. The
stock-nginx prototype config `deploy/cvmfs/nginx-proxy-cache.conf` already
implements both modes for the Phase-1 baseline).

CVMFS clients are *designed* to talk through a classic forward proxy: a site
sets `CVMFS_HTTP_PROXY="http://cache:3128"` and the client then issues
**absolute-URI** requests — `GET http://stratum1.cern.ch/cvmfs/repo/data/…`
— naming whichever Stratum-1 *the client* selected from `CVMFS_SERVER_URL`.
So in proxy mode the **client chooses the origin per request**; the cache
follows, constrained by `xrootd_cvmfs_upstream_allow` (host allowlist — this
is what keeps it from being an open proxy) and `xrootd_cvmfs_upstream_max`
(bounded lazy per-upstream backend registry). Client-side failover
bookkeeping stays in charge: a proxy that breaks connections gets skipped by
the client, which is why the fill path holds/retries rather than dropping
connections (never-drop semantics).

```
  client config: CVMFS_HTTP_PROXY=http://this-node:PORT
                 CVMFS_SERVER_URL="http://s1-a.cern.ch/…;http://s1-b.fnal.gov/…"

  ┌────────────┐  GET http://s1-a.cern.ch/cvmfs/repo/data/ab/cd…  (ABSOLUTE-URI:
  │ CVMFS      │ ───────────────────────────────────────────────▶  the CLIENT names
  │ client     │                                                    the origin)
  └────────────┘                        │
                                        ▼
                          ┌───────────────────────────┐
                          │  nginx-xrootd cvmfs proxy │
                          │  1. parse absolute-URI →  │
                          │     (upstream, path)      │
                          │  2. upstream ∈ allowlist? │──── no ──▶ 403 (open-proxy
                          │     (xrootd_cvmfs_        │            refusal; plain
                          │      upstream_allow)      │            https CONNECT is
                          │  3. cache key = path      │            refused too)
                          │     (CAS hash — same      │
                          │      object from ANY      │
                          │      stratum-1 dedupes)   │
                          └──────┬──────────┬─────────┘
                            HIT  │          │ MISS: dial the CLIENT-NAMED upstream
                                 ▼          ▼        (per-upstream lazy sd instance)
                          local CAS   ┌──────────────┐
                          store       │ s1-a.cern.ch │  ← chosen by the client,
                                      └──────────────┘    merely PERMITTED by us

  FORWARD because: the origin is in the request, not in our config. The
  allowlist is the security boundary — without it this is an open relay.
```

### 3.8 Traffic mirroring / shadow replay — out-of-band reverse fan-out

`src/net/mirror/` (`xrootd_mirror_url` for WebDAV, `xrootd_stream_mirror_url`
for root://, plus sampling/method/opcode masks). Not on the request path at
all: **after** the primary response has been sent, a sampled copy of the
request is replayed to up to 4 operator-configured shadow backends and the
shadow's status is compared against the primary's (divergence counted,
optionally logged). The client never sees or waits for the shadow.
Credentials are stripped (or a configured token injected) toward the shadow.
Three surfaces: HTTP background subrequests; a self-contained async XRootD
client for stateless stream ops; and a buffered `open→write→close` replay
for data writes (W3).

```
  ┌────────┐  1. request      ┌──────────────────┐  2. normal handling   ┌─────────┐
  │ CLIENT │ ───────────────▶ │   nginx-xrootd   │ ────────────────────▶ │ primary │
  │        │ ◀─────────────── │   (primary path) │ ◀──────────────────── │ storage │
  └────────┘  3. response     └────────┬─────────┘                       └─────────┘
              (client is DONE)         │
                                       │ 4. AFTER the response: sampled,
                                       │    fire-and-forget replay
                                       │    (credentials stripped/replaced)
                                       ▼
                              ┌─────────────────┐
                              │ shadow backend  │ ──▶ 5. shadow status vs primary
                              │ (≤4 targets)    │        status → divergence metric
                              └─────────────────┘        (response DISCARDED)

  Reverse-shaped (operator picks the shadows) but OUT-OF-BAND: no client
  byte ever depends on the shadow. Purpose: prove a new backend answers
  like production before cutover.
```

### 3.9 Third-party copy (TPC) — the forward-flavoured cousin

`src/tpc/` (native root:// TPC) and `src/protocols/webdav/tpc*.c` (HTTP TPC:
`COPY` with `Source:`/`Destination:` + `TransferHeader*` credentials). Not a
proxy — no client connection is being fronted — but it shares the forward
proxy's defining property: **the client names the remote endpoint in the
request**, and the server then acts as a *client* toward it, pulling (or
pushing) the file server-to-server on the client's behalf, with
client-supplied credentials for the far end.

```
  ┌────────┐  COPY /local/f                       ┌──────────────┐
  │ CLIENT │  Source: https://far.site/f  ──────▶ │ nginx-xrootd │
  │ (thin  │  TransferHeaderAuthorization: …      │ (destination)│
  │ orches-│ ◀── 201 + per-marker progress ────── │              │
  │ trator)│                                      └──────┬───────┘
  └────────┘                                             │ server acts as an HTTP/root
       control plane only —                              │ CLIENT toward the CLIENT-NAMED
       the DATA never touches                            ▼ source, using client-supplied creds
       the client's link                          ┌──────────────┐
                                                  │  far.site    │
                                                  │  (source)    │ ═══ bulk data ═══▶ destination
                                                  └──────────────┘
```

### 3.10 CMS redirection — the contrast case (not a proxy)

`src/net/cms/`, `src/net/manager/`. A redirector/manager **never carries
data**: the client logs in, asks for a file, and receives a `kXR_redirect`
to the data server that has it; the client reconnects *directly*. Both proxy
models keep the data path through the middle box — redirection removes the
middle box from the data path entirely. (Note the asymmetry with §3.1: the
terminating reverse proxy deliberately *follows* redirects itself so its
clients never see the cluster topology; a redirector deliberately *exposes*
a data server per file.)

```
  ┌────────┐  1. open /f          ┌────────────┐
  │ CLIENT │ ───────────────────▶ │ redirector │──── cms queries ───▶ data servers
  │        │ ◀─────────────────── │ (manager)  │     (who has /f?)
  │        │  2. kXR_redirect     └────────────┘
  │        │     "go to ds3:1094"
  │        │
  │        │  3. open /f (direct — redirector no longer involved)   ┌───────────┐
  │        │ ◀════════════════════════ data ═══════════════════════│ ds3:1094  │
  └────────┘                                                        └───────────┘
```

### 3.11 The tap — shared observation layer, not a proxy

`src/net/tap/` is a pure-C decoder + sink fan-out (no nginx, no allocation,
no OpenSSL) that turns raw XRootD wire bytes into frame descriptors
(streamid, opcode/status, errnum, path) and fans them out to registered
sinks (JSON audit today; metrics/capture slots exist). It is **fed by**
both root:// proxy modes rather than being a mode itself:

```
                    ┌─────────────────────────────┐
   §3.1 terminating │ full plaintext, both legs   │──▶ tap_decode ──▶ tap_emit ──▶ sinks
        proxy       │ (proxy terminated the TLS)  │                    │
                    └─────────────────────────────┘                    ├─▶ JSON audit log
                    ┌─────────────────────────────┐                    ├─▶ (metrics sink)
   §3.2 transparent │ whatever is CLEARTEXT on    │──▶ tap_stream ─────┘
        relay       │ the wire (relay sees no     │    (streaming, skips 20B
                    │ decrypted bytes)            │     handshake preamble C2U)
                    └─────────────────────────────┘
```

The coverage difference is the terminate-vs-relay trade-off in one line:
**terminating proxy = total visibility, holds credentials; transparent
relay = zero credential exposure, sees only cleartext.**

---

## 4. Choosing a model (decision guide)

```
Do you need nginx-xrootd to carry the data at all?
├─ no, just point clients at the right server ──────────────▶ CMS redirection (§3.10)
└─ yes
   Who must choose the origin?
   ├─ the CLIENT names it in the request
   │  ├─ CVMFS absolute-URI site proxy ─────────────────────▶ FORWARD proxy mode (§3.7)
   │  │                                                        + upstream allowlist (MANDATORY)
   │  └─ one-shot server-to-server transfer ────────────────▶ TPC (§3.9)
   └─ the OPERATOR configures it
      Should auth terminate at this node?
      ├─ NO — credentials must travel end-to-end untouched
      │  ├─ off-box upstream, want protocol audit ──────────▶ transparent relay (§3.2)
      │  └─ local port multiplexing (HTTP on the data port) ▶ http handoff (§3.3)
      └─ YES — this node is the perimeter
         Keep a local copy of the bytes?
         ├─ yes ── caching reverse proxy
         │         ├─ generic (root/dav/s3 front, any origin) ▶ read-through cache (§3.5)
         │         └─ CVMFS traffic specifically ─────────────▶ cvmfs:// reverse mode (§3.6)
         └─ no ─── pure terminating reverse proxy
                   ├─ root:// wire ───────────────────────────▶ xrootd_tap_proxy (§3.1)
                   └─ WebDAV/HTTP ────────────────────────────▶ perimeter proxy (§3.4)
Also, out of band: validating a NEW backend against live traffic ▶ mirroring (§3.8)
```

## 5. Security posture — what each model must get right

| Model | The invariant that keeps it safe | Where enforced |
|---|---|---|
| Forward (cvmfs proxy mode) | **Upstream allowlist** — an unconstrained forward proxy is an open relay for arbitrary origins (and `CONNECT`-style https tunneling is refused outright) | `xrootd_cvmfs_upstream_allow` + gate rejects; classifier admits only CVMFS traffic shapes |
| Terminating reverse | **Client auth at the perimeter** before anything is forwarded; upstream credentials are the *proxy's*, scoped by policy (anon/forward/token/SSS/GSI-delegated); paths rewritten under a fixed prefix | proxy dispatch runs only when `ctx->logged_in`; auth policy per upstream; audit log of every mutation |
| Transparent relay | **Touch nothing** — no frame is modified, no credential is held; the tap is read-only and sanitizes wire-derived strings before logging | relay pumps verbatim; `xrootd_sanitize_log_string()` on all logged paths |
| Caching reverse | **Verify on fill** (origin's advertised digest, or for CVMFS the hash embedded in the CAS URL) before publishing; admission/deny prefixes; never fabricate a checksum | `src/fs/cache/verify.c`, `cache_admit.c`; CVMFS CAS mode |
| Mirroring | **Never on the client path**; credentials stripped toward shadows; loop guard (`X-Xrootd-Mirror`); bounded buffers/response caps | `strip_auth`, loop-guard header, 64 KiB shadow-response cap |

---

*See also:* [`docs/10-architecture/`](../10-architecture/) for per-protocol
request lifecycles, and `docs/refactor/phase-68-cvmfs-site-cache.md` for the
CVMFS site-cache build-out (T14 = proxy mode).
