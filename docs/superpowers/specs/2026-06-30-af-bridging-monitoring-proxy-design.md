# Address-Family Bridging + Monitoring MITM Proxy — Design

**Date:** 2026-06-30
**Status:** Approved design (Phase 1 detailed; Phases 2–4 interface-level, own specs later)
**Author:** brainstorming session (Rob Currie)

---

## 1. Problem & Goals

Two related operational needs, unified under one architecture:

1. **Address-family bridging.** Accept dual-stack / IPv6 clients on the front
   door but reach an upstream/backend that is **IPv4-only** *or* **IPv6-only**.
   This must work for the read-through and write-through **caches** (origin
   connect) and for the new proxy (upstream connect). There is no protocol
   translation — the listen side stays dual-stack via nginx `listen`; only the
   *outbound* connection's address family is constrained.

2. **Monitoring MITM proxy** that listens on `root://` or `https`/XrdHttp and
   speaks the **same protocol** to an upstream **official XRootD** server, in
   two distinct modes:
   - **Terminating MITM** — the proxy authenticates the client, then
     re-authenticates upstream **as the user** using the user's own credential
     (WLCG/bearer token, SSS, username pass-through now; GSI X.509 proxy
     delegation later). Full plaintext visibility into the protocol.
   - **Transparent pass-through tap** — the proxy relays the raw byte stream
     client↔upstream **verbatim** (the auth handshake travels end-to-end, so
     X.509/GSI "just works" without the proxy holding any credential), and
     **passively decodes whatever is not encrypted** to monitor data in flight.

   Every decoded frame fans out to four observability sinks: **JSON audit log**,
   **Prometheus metrics**, **full-frame capture**, and a **live inspection
   hook**.

### Non-goals

- No protocol *translation* between families (it is all TCP / same wire
  protocol — only DNS-resolution family selection differs).
- No decryption of end-to-end TLS in transparent mode. A passive tap can only
  observe cleartext frames. XRootD's classic "authenticate but do not
  bulk-encrypt" mode (`root://` auth without TLS data encryption) is the regime
  where the transparent tap sees opcodes/paths/handles; a full-TLS client↔origin
  session yields only ciphertext to the tap, which is expected and documented.
- No new caching behavior — the transparent relay does not cache.

### Success criteria

- A cache node with an IPv6 (or dual-stack) front can fill from an IPv4-only
  origin (and vice versa) with a single config directive, with no ~2-minute
  connect stall when the wrong family is forced against an incompatible backend.
- The terminating proxy can present the client's bearer token / SSS / username
  to the upstream official XRootD server and relay the response unchanged.
- The transparent relay passes an X.509/GSI session through untouched while
  emitting audit + metrics for every cleartext frame it decodes.

---

## 2. Architecture (Approach C — shared core + thin adapters)

Three reusable pieces, wired into the existing cache + proxy paths plus one new
transparent-relay path.

```
                         ┌─────────────────────────────┐
   dual-stack listener   │  address-family selector    │   single-family
   (IPv6 + IPv4 clients) │  (auto | inet | inet6)      │   upstream/backend
                         └─────────────┬───────────────┘
                                       │ used by
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                                ▼
  cache origin connect         proxy upstream connect         (later: TPC / CMS)
        │                              │
        │                              ├── terminating MITM
        │                              │    (existing xrootd_proxy + cred-forward)
        │                              └── transparent relay
        │                                   (NEW: verbatim bytes, no auth-term)
        ▼                              ▼
                         ┌─────────────────────────────┐
                         │   tap core  (src/net/tap/)      │ decode frame → fan out
                         │   sinks: audit | metrics |  │
                         │          capture | hook     │
                         └─────────────────────────────┘
```

**Why Approach C** (vs. A = extend the two existing proxies in place, vs. B = a
fully separate `src/net/mirror/` subsystem): the tap and the family selector are each
implemented **once** and shared. The terminating MITM is the *existing*
`xrootd_proxy` (which already does connect, TLS, pooling, handle translation,
`kXR_wait`/`kXR_redirect` follow-through, splice) plus credential-forward
extensions; the transparent tap is a *thin* relay that reuses the proxy's connect
and splice plumbing but skips auth termination. A duplicates the tap across the
stream + http subsystems and fights the auth-terminating design; B reinvents
connect/TLS/pooling/frame-parsing the proxy already has.

### Unit boundaries

| Unit | Purpose | Depends on | Independently testable? |
|---|---|---|---|
| address-family selector | choose `AF_INET`/`AF_INET6`/`AF_UNSPEC` for an outbound resolve | `netconnect.h` getaddrinfo | yes — resolve-only unit test |
| tap core (`src/net/tap/`) | decode an XRootD frame header + fan out to sinks | nothing above it (pure) | yes — feed bytes, assert sink calls |
| audit / metrics / capture / hook sinks | one observable each | tap core sink API | yes — per-sink |
| terminating cred-forward | present user cred upstream | existing proxy bootstrap | yes — per auth method |
| transparent relay mode | verbatim byte relay + tap feed | proxy connect/splice + tap | yes — byte-equality + tap assertions |

---

## 3. Phase 1 — Address-family selector (DETAILED, implement first)

Small, high-value, unblocks the IPv4/IPv6 bridge for the caches immediately.

### 3.1 Type

Add to `src/protocols/root/connection/netconnect.h`:

```c
typedef enum {
    XROOTD_AF_AUTO  = AF_UNSPEC,   /* today's behaviour — default */
    XROOTD_AF_INET  = AF_INET,     /* IPv4-only upstream/backend  */
    XROOTD_AF_INET6 = AF_INET6     /* IPv6-only upstream/backend  */
} xrootd_af_policy_t;
```

Using the `AF_*` constants as the enum values lets the policy be assigned
straight into `hints.ai_family` with no mapping table.

### 3.2 Resolver changes (the two seams)

Both resolvers currently hardcode `hints.ai_family = AF_UNSPEC`:

1. **`xrootd_resolve_connect_socket()`** (`src/protocols/root/connection/netconnect.h`) — used by
   the event-driven outbound connectors (proxy upstream, `root://` upstream).
   Add an `xrootd_af_policy_t af_policy` parameter; set
   `hints.ai_family = (int) af_policy`. Update all existing callers to pass
   `XROOTD_AF_AUTO` (no behavior change) except where the new directive applies.

2. **`xrootd_cache_origin_connect_addr()`** (`src/fs/cache/origin_connection.c`) —
   read the configured policy off the cache fill ctx / origin config and set
   `hints.ai_family` from it.

The non-blocking connect + `poll(POLLOUT)` deadline already present in both paths
guarantees that forcing an incompatible family (e.g. `inet6` against an
IPv4-only backend whose name has no AAAA, or a reachable-but-wrong address)
fails fast via DNS-empty or connect-error — **no ~2-minute TCP retransmit
stall**. When `getaddrinfo` returns no addresses for the forced family the
caller emits its existing DNS-failure error (`kXR_ServerError` for the cache).

### 3.3 Config directives

No `./configure` needed — these attach to existing config blocks (merge with
`NGX_CONF_UNSET_UINT`, default `XROOTD_AF_AUTO`):

| Directive | Scope | Applies to |
|---|---|---|
| `xrootd_cache_origin_family auto\|inet\|inet6;` | cache server/location | read-through + write-through origin connect |
| `xrootd_proxy_upstream_family auto\|inet\|inet6;` | stream server (proxy) | default for all upstreams |
| `family=auto\|inet\|inet6` token on `xrootd_proxy_upstream` | per-upstream | per-endpoint override of the above |

A small shared parser `xrootd_af_policy_parse(ngx_str_t*) -> xrootd_af_policy_t`
(returns `NGX_CONF_UNSET_UINT`-compatible sentinel on a bad token) keeps the
three directive handlers DRY.

### 3.4 Tests (success + error + parity, per the 3-tests rule)

1. **Success** — configure `xrootd_cache_origin_family inet`, fill from an
   IPv4-only origin: byte-exact cached object, cinfo present.
2. **Error / no-stall** — `xrootd_cache_origin_family inet6` against an
   IPv4-only origin name (no AAAA): fill fails with a clean origin error well
   under the connect deadline (assert elapsed ≪ 120 s), no worker stall.
3. **Parity / security** — default (`auto`) origin fill is byte-identical to
   pre-change behavior; the dual-stack listener still accepts both IPv4 and IPv6
   *client* connections (the knob is outbound-only and does not touch `listen`).

---

## 4. Phase 2 — Tap core + audit/metrics sinks (interface-level)

New subsystem `src/net/tap/` (register new `.c` in the top-level `./config` source
list, then `./configure`).

### 4.1 Decoder + fan-out API (sketch)

```c
typedef enum { XROOTD_TAP_C2U, XROOTD_TAP_U2C } xrootd_tap_dir_t;

typedef struct {
    uint16_t  streamid;
    uint16_t  opcode;          /* request side */
    uint16_t  status;          /* response side */
    ngx_str_t path;            /* if decodable from this opcode */
    uint8_t   fhandle;         /* if present */
    uint64_t  offset;
    uint32_t  dlen;
    /* user identity is attached by the proxy ctx, not the wire frame */
} xrootd_tap_frame_t;

/* Called by both proxy modes for each decoded frame. Non-blocking; sinks that
 * would block (capture file) buffer or drop per their own policy. */
void xrootd_tap_emit(xrootd_tap_ctx_t *tap,
                     const xrootd_tap_frame_t *f,
                     xrootd_tap_dir_t dir,
                     const u_char *payload, size_t payload_len);
```

Sinks register at config time; `xrootd_tap_emit` fans out to the enabled set.

### 4.2 Sinks in Phase 2

- **Audit (JSON)** — reuse the existing proxy audit line format
  (`forward_relay_audit.c`) for path-mutation + open/close/read/write metadata,
  including the mapped user identity and status.
- **Metrics (Prometheus)** — low-cardinality only (INVARIANT #8: **no paths /
  bucket-names / UUIDs in labels**). Counters/histograms: ops by opcode, bytes
  in/out, upstream latency, error rate. Exported on the existing `/metrics`
  endpoint via the metrics module (enum in `metrics.h`, field in
  `metrics_internal.h`, `XROOTD_*_METRIC_INC`).

Wired into the **terminating** proxy first (it already has the decoded frames and
the user identity).

---

## 5. Phase 3 — Transparent relay + capture/hook (interface-level)

### 5.1 Transparent relay mode

A new proxy mode (e.g. `xrootd_proxy_mode transparent;` vs the default
`terminating`) that:

- Does **not** terminate the client's auth. After the TCP/listen accept it opens
  the upstream connection (honoring the Phase-1 family policy) and relays bytes
  **verbatim** in both directions — the client's `kXR_protocol`/`kXR_login`/
  `kXR_auth` handshake reaches the official upstream unchanged, so X.509/GSI,
  tokens, SSS all authenticate **end-to-end** with no credential held by the
  proxy.
- In parallel, runs a **non-consuming decoder** over the cleartext bytes it
  forwards and calls `xrootd_tap_emit` for each frame it can parse. Encrypted
  (TLS) segments are forwarded but yield no decodable frames (documented).
- Reuses the existing proxy `splice()` fast path for the byte relay where
  possible; the tap decode runs on the buffered copy when not spliced.

### 5.2 New sinks

- **Full-frame capture** — opt-in per session; decoded frame headers + cleartext
  payload to a capture file/stream for offline analysis. High volume → explicit
  enable + rotation/size cap.
- **Live inspection hook** — a registered in-line callback that sees each decoded
  frame and may alert (Phase 3) or later modify (out of scope here). Used for
  flagging specific paths/users.

---

## 6. Phase 4 — GSI X.509 proxy delegation upstream (interface-level, HIGH RISK)

Isolated so it cannot hold up Phases 1–3. To act **as the user** upstream under
GSI in *terminating* mode, the proxy needs the client's delegated X.509 proxy
chain and must drive an `XrdSecgsi` exchange to the upstream presenting it.

**Risk callout:** native `root://` TPC over GSI is already known-broken in this
codebase (dest never triggers pull, `exchange()` round-2 is dead code — see the
"Native TPC GSI is broken" memory). GSI delegation forwarding builds on the same
fragile foundation and is expected to be multi-day. This phase gets its own spec
and is explicitly **not** a dependency of the transparent mode (where GSI already
works end-to-end because the proxy does not terminate it).

---

## 7. Cross-cutting rules honored

- **HELPERS / no reimplementation** — reuse `xrootd_resolve_connect_socket`,
  proxy connect/splice/pool, the existing audit line builder, the metrics
  macros, `resolve_path` (not relevant to relay but to any local resolution).
- **No `goto`**, functional/modular, explicit ctx — new tap code passes a
  `xrootd_tap_ctx_t`, no new globals.
- **Metric cardinality** (INVARIANT #8) — strictly enforced in the metrics sink.
- **Build governance** — Phase 1 touches existing blocks only (no `./configure`);
  Phase 2+ add new `.c` files → register in top-level `./config`, then
  `./configure`.
- **3 tests per change** — success + error + security/parity, per phase.

---

## 8. Phasing summary

| Phase | Scope | Risk | Gating |
|---|---|---|---|
| 1 | Address-family selector (cache + proxy outbound) | low | none — ships standalone |
| 2 | Tap core + audit + metrics, into terminating proxy | medium | needs new src files |
| 3 | Transparent relay + capture + hook | medium | depends on tap core (P2) |
| 4 | GSI X.509 delegation upstream (terminating) | **high** | isolated; not a dep of P3 |

Phase 1 is specified above in full and is the first implementation target.
Phases 2–4 are specified at the interface level and each get their own
spec + plan + implementation cycle.
