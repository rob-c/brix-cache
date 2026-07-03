# Proxy Mode

BriX-Cache as a protocol-aware forwarding proxy — authenticates clients itself (GSI, token, or anonymous), then forwards authenticated requests upstream to a real XRootD data server. Useful when you want centralized auth without touching the backend.
then lazily connects to the upstream on the first data-plane request and relays
all subsequent opcodes — rewriting file handles transparently so neither side
knows about the other's handle space.

---

## Where the proxy sits

```
                      ┌─────────────────────────────────────────┐
                      │          nginx-xrootd proxy             │
                      │                                         │
 Client               │  ┌───────────────┐  ┌───────────────┐  │
 (xrdcp / xrootd) ────┼─►│  auth layer   │  │  upstream ctx │  │
                  TLS │  │  (GSI/token/  │  │  fh_map[16]   │  │
                      │  │   anonymous)  │  │  bootstrap    │  │
                      │  └───────┬───────┘  └───────┬───────┘  │
                      │          │  dispatch         │          │
                      │          └───────────────────┘          │
                      └────────────────────┬────────────────────┘
                                           │  plain TCP
                                           ▼
                               ┌───────────────────────┐
                               │  upstream xrootd      │
                               │  (xrdceph, POSIX,     │
                               │   xrootd-hdfs, tape…) │
                               └───────────────────────┘
```

The proxy terminates the client-facing TLS and speaks XRootD on both sides. The
upstream connection is plain TCP (unauthenticated anonymous login). Clients see a
standard XRootD server; the upstream sees standard XRootD client connections.

---

## Quick start

### Minimal config

```nginx
# nginx.conf
worker_processes 1;

events { worker_connections 256; }

stream {
    server {
        listen 1094;

        xrootd on;
        xrootd_auth none;          # client auth: anonymous

        xrootd_proxy on;
        xrootd_proxy_upstream xrootd.example.org:1094;
    }
}
```

That is the complete config. The `xrootd_proxy_upstream` directive accepts
`host`, `host:port`, or an IPv6 literal `[::1]:1094`. Default port is 1094 if
omitted.

### With TLS on the client-facing side

```nginx
stream {
    server {
        listen 1095 ssl;

        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;

        xrootd on;
        xrootd_auth token;
        xrootd_token_jwks   /etc/xrootd/jwks.json;

        xrootd_proxy on;
        xrootd_proxy_upstream storage.internal:1094;
    }
}
```

> **Note:** The outbound connection to the upstream is plain TCP by default.
> Enable `xrootd_proxy_upstream_tls on` for an encrypted upstream connection,
> with optional CA verification (`xrootd_proxy_upstream_tls_ca`) and SNI
> override (`xrootd_proxy_upstream_tls_name`).

### Testing with xrdcp

```sh
# Point at the proxy; file is fetched transparently from the upstream
xrdcp root://proxy.example.org//store/data/file.root /tmp/file.root

# With token auth
BEARER_TOKEN_FILE=/tmp/token \
  xrdcp roots://proxy.example.org//store/data/file.root /tmp/file.root
```

---

## How it works

### Bootstrap: lazy upstream connection

The proxy does not connect to the upstream at config load time or at client
login. It connects on the **first post-login opcode** that is not a session
opcode (kXR_ping, kXR_query, kXR_endsess). This means a client that only pings
or ends its session never causes an upstream TCP connection.

```
Client              Proxy                     Upstream
  │                   │                          │
  │── handshake ─────►│                          │
  │◄─ server hello ───│                          │
  │── kXR_protocol ──►│                          │
  │◄─ ok ─────────────│                          │
  │── kXR_login ─────►│                          │
  │◄─ ok ─────────────│                          │
  │                   │                          │
  │── kXR_ping ──────►│ (handled locally)        │
  │◄─ ok ─────────────│                          │
  │                   │                          │
  │── kXR_stat ──────►│── TCP connect ──────────►│
  │   (queued)        │── handshake ────────────►│
  │                   │◄─ server hello ───────────│
  │                   │── kXR_protocol ─────────►│
  │                   │◄─ ok ─────────────────────│
  │                   │── kXR_login (anon) ──────►│
  │                   │◄─ ok ─────────────────────│
  │                   │                  bootstrap │
  │                   │── kXR_stat ─────────────►│
  │◄─ ok (stat body) ─│◄─ ok ─────────────────────│
```

If the client's first opcode arrives while the bootstrap TCP connect is still in
progress (common on non-loopback links), the request is saved and replayed the
moment bootstrap completes. The client waits transparently.

> **Implementation note:** Bootstrap sends all three frames (client hello +
> kXR_protocol + kXR_login) in a single write. It uses edge-triggered epoll and
> loops reading bootstrap responses without returning to the event loop, so all
> three upstream replies can arrive in a single TCP segment without stalling.
> This loop-in-read-handler pattern was a deliberate fix for the ET epoll
> bootstrap stall bug.

### Open and handle translation

XRootD file handles are single-byte integers scoped to one TCP session. Client
session and upstream session assign handles independently; the proxy translates
between them on every file-handle opcode.

```
Client              Proxy                     Upstream
  │                   │                          │
  │── kXR_open ──────►│  alloc local fh=2        │
  │   path=/data.root │── kXR_open ─────────────►│
  │                   │◄─ ok (upstream fh=0) ─────│
  │                   │  fh_map[2] = 0            │
  │◄─ ok (fh=2) ──────│  (rewrite fh in body)     │
  │                   │                          │
  │── kXR_read fh=2 ─►│  translate: fh 2 → 0     │
  │                   │── kXR_read fh=0 ─────────►│
  │◄─ data ───────────│◄─ data ───────────────────│
  │                   │                          │
  │── kXR_close fh=2 ►│  translate: fh 2 → 0     │
  │                   │── kXR_close fh=0 ────────►│
  │◄─ ok ─────────────│◄─ ok ──────────────────────│
  │                   │  fh_map[2] = FREE         │
```

The `fh_map` table has 16 slots (`XROOTD_MAX_FILES`). A client can have up to
16 files open simultaneously. Attempting a 17th open returns `kXR_IOError` with
the message `proxy: no free file handles`.

If a kXR_open fails at the upstream, the pre-allocated local slot is freed
immediately so it can be reused.

### Read relay and kXR_oksofar streaming

For large reads the upstream may respond with a sequence of `kXR_oksofar`
frames followed by a final `kXR_ok`. The proxy relays each frame to the client
as it arrives, staying in `XRD_PX_FORWARDING` state until the final frame:

```
Client              Proxy                     Upstream
  │                   │                          │
  │── kXR_read ──────►│── kXR_read ─────────────►│
  │                   │                          │
  │◄─ oksofar chunk 1─│◄─ oksofar chunk 1 ────────│
  │◄─ oksofar chunk 2─│◄─ oksofar chunk 2 ────────│
  │◄─ ok (last chunk)─│◄─ ok (last chunk) ────────│
  │                   │  state → IDLE            │
```

Response bodies are heap-allocated (up to 16 MiB per frame). The upstream
stream-ID in each response header is replaced with the client's original
stream-ID before forwarding.

### Vectored reads (kXR_readv)

`kXR_readv` requests carry an array of `readahead_list` entries, each 16 bytes:
`fhandle[4] + rlen[4] + offset[8]`. The proxy walks every entry and translates
the fhandle field in-place before forwarding. This means a single `kXR_readv`
can reference handles from different files as long as all handles are open and
in the fh_map.

### Error propagation

All upstream error responses (`kXR_error`) are relayed verbatim to the client
with the original stream-ID. A backend error does not close the connection or
corrupt proxy state. Pre-allocated fh_map slots are freed on failed opens so
they can be reused immediately.

---

## Configuration reference

| Directive | Context | Default | Description |
|---|---|---|---|
| `xrootd_proxy on\|off` | `server` | `off` | Enable proxy mode for this server block. Requires `xrootd on`. |
| `xrootd_proxy_upstream host[:port] [auth]` | `server` | — | Upstream XRootD server. Port defaults to 1094. Accepts hostnames, IPv4, and IPv6 literals. May appear multiple times; connections are distributed round-robin. Optional `auth` argument overrides the server-level `xrootd_proxy_auth` for this upstream only: `anonymous`, `forward`, `sss`, or `sss:<keyname>`. Required when `xrootd_proxy on`. |
| `xrootd_proxy_upstream_tls on\|off` | `server` | `off` | Wrap the outbound upstream connection in TLS. |
| `xrootd_proxy_upstream_tls_ca <path>` | `server` | — | PEM CA bundle to verify the upstream TLS certificate. Enables `SSL_VERIFY_PEER`. |
| `xrootd_proxy_upstream_tls_name <host>` | `server` | — | SNI hostname sent during the TLS handshake; defaults to the `xrootd_proxy_upstream` hostname. |
| `xrootd_proxy_auth anonymous\|forward\|sss` | `server` | `anonymous` | Upstream auth: `anonymous` sends no credentials; `forward` replays a bearer token received from the client; `sss` generates an SSS credential from the first `xrootd_sss_key` entry. |
| `xrootd_proxy_audit_log <path>\|off` | `server` | `off` | Write one JSON line per closed or abandoned upstream file handle. |
| `xrootd_proxy_reconnect_attempts <n>` | `server` | `0` | How many times to reconnect to the upstream (and redo bootstrap) when the connection drops while idle with no open handles. |
| `xrootd_proxy_connect_timeout <ms>` | `server` | `10000` | Milliseconds allowed for the upstream TCP connect to complete. `0` disables the timer. |
| `xrootd_proxy_read_timeout <ms>` | `server` | `60000` | Milliseconds of silence from the upstream before the connection is aborted. `0` disables the timer. |
| `xrootd_proxy_path_rewrite <strip> <add>` | `server` | — | Rewrite paths on kXR_open and all path-based requests: strip the leading `strip` prefix (no-op if path does not start with it) then prepend `add`. Example: `xrootd_proxy_path_rewrite /xrootd /data` maps `/xrootd/file.root` → `/data/file.root`. |
| `xrootd_proxy_keepalive_interval <time>` | `server` | `15s` | kXR_ping interval for idle pooled upstream connections. Accepts nginx time values (`15s`, `1m`, etc.). Set to `0` to disable keepalives on pooled connections. |

All directives live inside a `stream { server { } }` block. They are not
valid inside `http { }`.

> **Tip:** `xrootd_auth` on the client-facing side is independent of the
> upstream connection. You can accept token-authenticated clients and connect
> anonymously to the upstream, or accept anonymous clients and still require
> the upstream to be reachable.

---

## What's implemented now vs what's planned

### Implemented

| Feature | Notes |
|---|---|
| ✅ Lazy upstream TCP connect on first FS opcode | Triggered by kXR_stat, kXR_open, kXR_dirlist, etc. — not by kXR_ping/kXR_query |
| ✅ XRootD bootstrap to upstream (handshake + kXR_protocol + kXR_login) | Anonymous login, username "xrd", unique virtual PID per connection |
| ✅ Client-side auth: anonymous, GSI, token, sss | Normal BriX-Cache auth stack |
| ✅ File handle translation (fh_map[16]) | Per-connection; client handles are independent of upstream handles |
| ✅ kXR_open — pre-allocate local slot, rewrite upstream fh in response | Failed opens free the slot immediately |
| ✅ kXR_read, kXR_pgread, kXR_write, kXR_pgwrite, kXR_close, kXR_sync, kXR_chkpoint | fh translated at byte 0 of request body |
| ✅ kXR_readv, kXR_writev | Per-entry fh translation across the entire payload |
| ✅ kXR_clone | Both src_fhandle and dst_fhandle translated |
| ✅ kXR_stat, kXR_truncate, kXR_fattr | fh translated only when non-zero (path-based if zero) |
| ✅ All path-based ops forwarded verbatim | kXR_dirlist, kXR_locate, kXR_mkdir, kXR_rm, kXR_rmdir, kXR_mv, kXR_prepare, kXR_query, etc. |
| ✅ kXR_oksofar streaming relay | Each chunk forwarded as it arrives; state stays FORWARDING until final ok |
| ✅ Request saved during bootstrap | If a client request arrives before bootstrap completes, it is saved and replayed |
| ✅ Upstream error relay | kXR_error body forwarded verbatim with client stream-ID |
| ✅ Graceful upstream-unavailable handling | kXR_IOError returned to client; connection remains usable for session opcodes |
| ✅ Upstream TLS | `xrootd_proxy_upstream_tls on` + optional CA verification and SNI override |
| ✅ Auth bridging: token forward + SSS credential generation | `xrootd_proxy_auth forward` replays bearer token; `sss` builds SSS credential from configured key |
| ✅ JSON audit log per close | `xrootd_proxy_audit_log`; one JSON line with user, path, bytes, duration |
| ✅ Metrics collection hooks | `proxy_*` counters on the `/metrics` endpoint |
| ✅ kXR_bind / secondary data channels | Bound secondaries get their own upstream connection; lazy-open resolves unresolved file handles including multi-handle kXR_readv |
| ✅ Upstream reconnect on idle drop | `xrootd_proxy_reconnect_attempts` redoes bootstrap transparently |
| ✅ Multiple upstream endpoints with round-robin | Multiple `xrootd_proxy_upstream` lines; connections are distributed evenly |
| ✅ Connect and read timeouts | `xrootd_proxy_connect_timeout`, `xrootd_proxy_read_timeout` |
| ✅ Path rewriting | `xrootd_proxy_path_rewrite <strip> <add>` applied to kXR_open and all path-based requests |
| ✅ kXR_endsess forwarding | Fire-and-forget endsess to upstream before local cleanup |
| ✅ Per-upstream credential isolation | Optional auth policy on each `xrootd_proxy_upstream` line overrides server-level `xrootd_proxy_auth`; supports per-upstream SSS key selection |
| ✅ Path-op audit log | `xrootd_proxy_audit_log` emits a JSON record for rm, mkdir, rmdir, mv, chmod, and path-based truncate when the response arrives; includes op, path(s), status, and login username |
| ✅ kXR_wait transparent retry for kXR_open | Upstream kXR_wait responses on open are absorbed; the open is re-issued after the requested delay (capped at 30 s); up to 5 retries before propagating the wait to the client |
| ✅ Proxy reconnect/path-op/wait metrics | `xrootd_proxy_reconnects_total`, `xrootd_proxy_path_ops_total`, `xrootd_proxy_path_op_errors_total`, `xrootd_proxy_wait_responses_total` on the `/metrics` endpoint |
| ✅ Per-upstream metric labels | All proxy Prometheus counters emit both an aggregate `{port,auth}` row and per-upstream `{port,auth,upstream="host:port"}` rows when multiple `xrootd_proxy_upstream` lines are configured; covers connects, errors, opens, reads, writes, closes, and more |
| ✅ Upstream connection pooling | Bootstrapped upstream connections are returned to a worker-local pool on client disconnect and reused by subsequent sessions; `kXR_ping` keepalives detect stale connections; pool size capped at 32, idle timeout 60 s |
| ✅ Upstream health tracking and failover | Per-upstream failure counter; after 3 consecutive connect failures an upstream is marked DOWN and skipped for 10 s; automatically re-enabled on next successful bootstrap |
| ✅ Login username passthrough | `xrootd_proxy_login_user passthrough` copies the client's authenticated username into the upstream `kXR_login` frame (max 8 chars); `fixed:<name>` sends a literal name; default `anonymous` sends "xrd" |
| ✅ kXR_redirect follow-through | Upstream redirects are followed transparently (up to 3 hops); the proxy reconnects to the redirected server and replays the in-flight request so clients behind NAT are not exposed to data-server addresses |
| ✅ kXR_wait absorption for non-open ops | kXR_wait transparent retry covers kXR_stat, kXR_locate, kXR_prepare, and all other non-open ops in addition to kXR_open; same timer and 5-retry cap |
| ✅ Configurable upstream keepalive interval | `xrootd_proxy_keepalive_interval` sets the kXR_ping cadence for pooled idle connections (default 15 s); `0` disables pings |
| ✅ Zero-copy splice for read data | kXR_read and kXR_pgread responses are moved directly from the upstream fd to the client fd via Linux `splice(2)` when both sides are plain TCP; automatic fallback to heap-buffer path when TLS is in use |

### Still needed

The items below are the remaining gaps between what is implemented and a
production-grade XRootD proxy.  They are grouped by area and roughly ordered
by operational impact.

#### Protocol correctness

| Feature | Current behaviour | What is needed |
|---|---|---|
| **kXR_waitresp / kXR_attn** | `kXR_waitresp` (4006) is forwarded to the client; the async completion arrives as an unsolicited `kXR_attn` (4001) on the upstream connection, which the proxy has no handler for. | Add an unsolicited-frame path in the upstream read handler that matches `kXR_attn` bodies to pending `kXR_waitresp` stream IDs and relays them to the correct client. |
| **kXR_prepare path rewriting** | `kXR_prepare` bodies contain a NUL-separated list of paths; the proxy's `proxy_rewrite_path()` treats the whole payload as a single path. | Parse the prepare body properly and apply `xrootd_proxy_path_rewrite` to each path entry when it is configured. |

#### Auth and identity

| Feature | Current behaviour | What is needed |
|---|---|---|
| **GSI credential bridging** | A GSI-authenticated client cannot be bridged to a GSI-speaking upstream. The proxy holds no service certificate for upstream presentation. | Add `xrootd_proxy_auth gsi` mode: present a configured service cert to the upstream `kXR_auth` challenge; requires `xrootd_proxy_upstream_cert` / `xrootd_proxy_upstream_key` directives. |
| **IAM token exchange (GSI → token)** | No token exchange is implemented. | For sites where the upstream speaks token auth: call a configured IAM `/token` endpoint with the client's GSI DN to obtain a short-lived bearer token, then use the existing `XROOTD_PROXY_AUTH_FORWARD` path. |

---

## Troubleshooting

### Proxy stalls on first request, then works

**Symptom:** the first `xrdcp` or `xrd_cp` call after nginx starts takes a few
seconds longer than expected; subsequent calls are fast.

**Cause:** this is normal for the first connection. The upstream TCP connect and
three-frame bootstrap happen on demand and add one RTT. Subsequent requests on
the same connection go directly to `XRD_PX_IDLE` state and are forwarded
immediately.

If the stall is long (> 5 s) or the connection eventually returns `kXR_IOError`,
check:
- Is the upstream reachable? `nc -zv upstream.host 1094`
- Is the upstream requiring authentication? Look for `upstream requires
  authentication (not yet supported)` in nginx's error log.
- Is the upstream requiring TLS? Look for `upstream requires TLS (not supported
  on proxy outbound)`.

### "proxy: no free file handles" error

**Symptom:** `kXR_open` returns `kXR_IOError` with `proxy: no free file
handles`.

**Cause:** the client has 16 files open simultaneously (`XROOTD_MAX_FILES`).
This is the XRootD wire-protocol limit; the 1-byte handle field supports at most
255 values and the implementation reserves 16 slots.

**Fix:** close files before opening new ones, or restructure the workload to use
fewer simultaneous open handles. There is no config knob; the limit is
compile-time.

### Backend errors visible on every request

**Symptom:** all `kXR_stat` or `kXR_open` calls return `kXR_error` with
messages from the upstream daemon.

**Cause:** the proxy relays upstream errors verbatim. If the upstream is
returning errors for every request (wrong root path, permission denied, quota
exhausted) those errors reach the client as-is.

**Diagnosis steps:**

1. Connect directly to the upstream with `xrdcp root://upstream.host//path`:
   does it work?
2. Check the upstream xrootd daemon's log for the anonymous login from the
   proxy (username `xrd`, originating from the proxy's IP).
3. If the upstream has an authdb or path-based ACL, ensure anonymous access to
   the required paths is permitted.

> **Tip:** Enable nginx debug logging temporarily to see every proxy state
> transition: `error_log /var/log/nginx/error.log debug;`. Look for lines
> beginning with `xrootd proxy:`.
