# The CMS Cluster Protocol (`cms://`)

What actually happens on the wire between a CMS **manager** and the servers and
clients it coordinates — the framing, the field-by-field negotiation in both
directions, and the non-obvious details that make nginx-xrootd
**cmsd-wire-compliant** with a real XRootD `cmsd`.

> **Naming.** There is no real `cms://` URL scheme. We use `cms://` here purely
> as an analogy to `root://`: just as `root://` is the *data* protocol a client
> speaks to a data server, **CMS** (Cluster Management Services) is the
> *control* protocol a data server speaks to its manager, and a manager speaks
> to its clients-of-record. It rides its own dedicated TCP connection on its own
> port (XRootD convention: `1213`), completely separate from the `root://` data
> port (`1094`).

This page is the **wire reference**. For *why you'd deploy it* and *how to
configure topologies*, see:

- [Cluster Management](../05-operations/cluster-management.md) — redirector / manager / cache architecture and config.
- [Hierarchical Cluster](../05-operations/hierarchical-cluster.md) — multi-tier (meta-manager → sub-manager → leaf) topology and the M-step implementation log.
- [Manager Mode](../05-operations/manager-mode.md) — the static `xrootd_manager_map` alternative.

Authoritative upstream spec (verified against XRootD 5.9.2):
`XProtocol/YProtocol.hh` (codes/structs), `XrdCms/XrdCmsLogin.cc` (login),
`XrdCms/XrdCmsParser.cc` (Pup field vectors), `XrdOuc/XrdOucPup.cc` (encoding),
`XrdCms/XrdCmsNode.cc` (do_Locate / do_State / do_Have / do_Status).

---

## 1. Where CMS sits

A managed XRootD cluster has three actors. nginx-xrootd can play any of them,
and a sub-manager plays two at once.

```
        root:// data port (1094)           CMS control port (1213)
   ┌──────────────────────────────┐   ┌──────────────────────────────┐
   │                              ▼   ▼                              │
Client  ── kXR_open/locate ──►  MANAGER  ◄── kYR_login/load ──  DATA SERVER
   │                              │                                 ▲
   │  ◄── kXR_redirect ──────────┘                                 │
   └────────────── root:// to the selected data server ────────────┘
```

| Role | `root://` side | CMS side | nginx-xrootd directives |
|---|---|---|---|
| **Data server** (leaf) | serves files | **outbound** CMS *client* → registers with manager | `xrootd_cms_manager`, `xrootd_cms_paths` |
| **Manager / redirector** | answers `kXR_locate`/`kXR_open` with `kXR_redirect` | **inbound** CMS *server* ← accepts data-server registrations | `xrootd_manager_mode on`, `xrootd_cms_server on` |
| **Sub-manager** | redirector to its children | **both**: outbound client to parent **and** inbound server to children | all of the above together |

The key invariant: **the manager never moves file bytes.** It keeps a live map
of "which server holds which path, and how loaded is it," and turns every client
lookup into a redirect. CMS is the protocol that keeps that map current.

nginx-xrootd implements two independent halves of this, in two source trees:

| Half | Direction | Source | Role it enables |
|---|---|---|---|
| **CMS client** | nginx → upstream manager | `src/net/cms/{connect,send,recv,wire,space}.c` | data server, sub-manager (upward) |
| **CMS server** | data servers → nginx | `src/net/cms/server_*.c` + `src/net/manager/{registry,redir_cache,pending}.c` | manager, sub-manager (downward) |

---

## 2. Frame anatomy — `CmsRRHdr`

Every CMS frame, in either direction, begins with the same fixed 8-byte header,
**all fields big-endian (network order)**:

```
 offset  size  field      meaning
 ──────  ────  ─────────  ──────────────────────────────────────────────
   0      4    streamid   correlation id (request ↔ reply); 0 = unsolicited
   4      1    rrCode     opcode (kYR_*)  — see §4
   5      1    modifier   opcode-specific flag bits
   6      2    dlen       payload length in bytes (0 for header-only frames)
 ──────
   8    dlen   payload    opcode-specific body (see §5–§7)
```

Implemented as `NGX_XROOTD_CMS_HDR_LEN = 8`. The big-endian get/put helpers live
in `src/net/cms/wire.c` (`ngx_xrootd_cms_get16/get32`, `put16/put32`). The frame
reader (`src/net/cms/recv.c`, `src/net/cms/server_recv.c`) reads exactly 8 bytes, decodes
`dlen` at offset 6, then reads `dlen` more bytes before dispatching. A frame whose
`dlen + 8` exceeds `NGX_XROOTD_CMS_MAX_FRAME` (4096) is rejected and the
connection is dropped — a cheap guard against a desynchronised or hostile peer.

### `streamid` semantics

- **`0`** for unsolicited frames a node emits on its own schedule (`kYR_login`,
  `kYR_load`, `kYR_status`, `kYR_pong` … the heartbeat traffic).
- **Echoed** on request/reply pairs so the originator can correlate: a manager's
  `kYR_state` carries a streamid, and the server's `kYR_have` reply **echoes the
  same value**; a sub-manager's `kYR_locate` carries a per-worker monotonic
  streamid (`ngx_xrootd_cms_next_streamid()`), and the parent's `kYR_select`
  echoes it so the right suspended client session is woken (§7).

---

## 3. Payload encoding — XrdOucPup (the part everyone gets wrong)

Inside the payload, fields use XRootD's `XrdOucPup` packing. There are **two
distinct sub-formats**, and mixing them up is the single most common
interop bug.

### Scalars are *type-tagged*

A leading tag byte announces the width, followed by the big-endian value:

| Type | Tag | Bytes | Encoder |
|---|---|---|---|
| short (u16) | `0x80` (`CMS_PT_SHORT`) | tag + 2 = 3 | `ngx_xrootd_cms_put_short()` |
| int (u32) | `0xa0` (`CMS_PT_INT`) | tag + 4 = 5 | `ngx_xrootd_cms_put_int()` |
| longlong (u64) | `0xc0` | tag + 8 = 9 | (not emitted by nginx) |

### Strings are **NOT** tagged

A string is a bare `[2-byte big-endian length][raw bytes]` — **no tag byte** —
and the length **includes the trailing NUL**:

```
 "/data"  →  00 06   2f 64 61 74 61 00       (len = strlen+1 = 6)
 ""/NULL  →  00 00                            (empty/absent string)
```

Encoder: `ngx_xrootd_cms_put_string()` in `src/net/cms/wire.c`. The real
`XrdCmsParser` distinguishes a string from a scalar **by the absence of the
`0x80` high bit in the first length byte** — which is why a string must never
carry a `PT_short`/`PT_int` tag.

> **The historical bug (now fixed).** nginx-xrootd's first login attempt encoded
> the path list as a *tagged short* (`put_short(len) + raw`) and omitted the
> SID/ifList/envCGI strings. The real parser, expecting a bare Pup string after
> the `sPort` field, saw a `0x80…` tag where a length was due → "invalid login
> data" → connection rejected. The fix (`put_string` = bare `[len][data+NUL]`,
> all four trailing strings emitted) is what makes a real `cmsd` accept us today.
> See §8.

There is also a special raw form used by `kYR_state`/`kYR_have` (a NUL-terminated
path with **no Pup framing at all** — §6.3), and a "bare blob" used by `kYR_load`
(`[len][bytes]` with no tag — §6.2). Knowing which frame uses which form is the
whole game.

---

## 4. Opcode catalogue (`kYR_*`)

From `src/net/cms/cms_internal.h`. Numeric values are wire constants — never
renumber.

| Constant | `rrCode` | Direction | Purpose |
|---|---|---|---|
| `CMS_RR_LOGIN`  | 0  | both | announce identity + capacity (handshake) |
| `CMS_RR_LOCATE` | 2  | (sub)manager → parent | "where is `<path>`?" — escalate a lookup |
| `CMS_RR_SELECT` | 10 | manager → node | "send the client to this one host" |
| `CMS_RR_AVAIL`  | 12 | node → manager | free space + utilisation reply |
| `CMS_RR_GONE`   | 14 | server → manager | data server dropped a specific path |
| `CMS_RR_HAVE`   | 15 | server → manager | "yes, I hold `<path>`" (raw) |
| `CMS_RR_LOAD`   | 16 | node → manager | periodic unsolicited load/space heartbeat |
| `CMS_RR_PING`   | 17 | manager → node | liveness probe (header-only) |
| `CMS_RR_PONG`   | 18 | node → manager | liveness reply (header-only) |
| `CMS_RR_SPACE`  | 19 | manager → node | "report your free space now" |
| `CMS_RR_STATE`  | 20 | manager → server | "do you hold `<path>`?" (raw, on-demand select) |
| `CMS_RR_STATUS` | 22 | both | suspend / resume / staging traffic control |
| `CMS_RR_TRY`    | 24 | manager → node | redirect with an *ordered list* of alternatives |

### `modifier` bit fields

**`kYR_status` modifier (`CMS_ST_*`)** — corrected to the real `CmsStatusRequest`
values (the early nginx constants had `SUSPEND`/`RESUME` swapped and wrong — §8):

| Bit | Value | Meaning |
|---|---|---|
| `CMS_ST_STAGE`   | `0x01` | staging available |
| `CMS_ST_NOSTAGE` | `0x02` | staging unavailable (disk-only node) |
| `CMS_ST_RESUME`  | `0x04` | resume accepting requests |
| `CMS_ST_SUSPEND` | `0x08` | stop accepting new requests |
| `CMS_ST_RESET`   | `0x10` | reset state |

**Request modifiers** — used by the raw on-demand-select path:

| Bit | Value | Meaning |
|---|---|---|
| `CMS_MOD_RAW`     | `0x20` | payload is raw (not Pup-encoded) — set on `kYR_state` & `kYR_have` |
| `CMS_HAVE_ONLINE` | `0x01` | (in `kYR_have`) the file is online / resident |

---

## 5. Negotiation A — nginx as data server (outbound CMS client)

This is the `src/net/cms/` client half. One **independent connection per nginx
worker** (see §8) is opened to `xrootd_cms_manager`. Lifecycle in
`src/net/cms/connect.c`:

```
worker init ──► ngx_xrootd_cms_start()           (arm 1 s initial-delay timer)
                     │
                     ▼
            ngx_xrootd_cms_connect()              (ngx_event_connect_peer, non-blocking)
                     │ TCP up (write event)
                     ▼
            write handler:
              1. send kYR_login            ─────────────────►  manager
              2. send kYR_status(Resume|noStage) ────────────►  manager
              3. send kYR_load             ─────────────────►  manager
              4. arm heartbeat timer (xrootd_cms_interval s)
                     │
        ┌────────────┴──── steady state ───────────────┐
        │  timer  → send kYR_load                       │
        │  manager kYR_ping  → reply kYR_pong           │
        │  manager kYR_space → reply kYR_avail          │
        │  manager kYR_state → stat() → reply kYR_have  │
        │  manager kYR_status→ set/clear cms_suspended  │
        └───────────────────────────────────────────────┘
```

Any I/O error or timeout → `ngx_xrootd_cms_disconnect()` → exponential backoff
retry (`6 s → … → 60 s`, capped, in `ngx_xrootd_cms_schedule_retry()`).

#### Fast cold-start settling (mesh formation)

When a whole cluster boots together — most acutely with several roles on **one host**
— a node's first connect frequently races ahead of its manager's listen socket and is
refused. To keep that from costing the multi-second backoff per node (which compounds
per tier in a meta→sub-manager→leaf mesh), `ngx_xrootd_cms_schedule_retry()` runs a
**fast-retry regime while a node has never yet logged in**: it retries the connect on a
short fixed interval for a bounded window, then falls back to exponential backoff. A
loopback manager (`127.0.0.0/8` / `::1`) gets the most aggressive profile, so same-host
meshes register within tens of milliseconds of the manager appearing instead of
seconds. Each node logs its settle time once:

```
xrootd: CMS registered with 127.0.0.1:2131 after 0 ms (1 connect attempt(s), loopback)
```

Defaults (tunable via `xrootd_cms_initial_delay` / `xrootd_cms_connect_retry`):
loopback = 0 ms initial delay, 10 ms retry, 2 s window; remote = 10 ms / 75 ms / 3 s.
The fast-retry is gated on *pre-first-login* and a *bounded window* and the interval is
floored at 10 ms, so it can never become a busy-spin; a reconnect **after** a node has
registered (a real outage) always uses the normal backoff. See
[`docs/09-developer-guide/lifecycle-startup-shutdown-performance.md`](../09-developer-guide/lifecycle-startup-shutdown-performance.md)
for the measurement approach this shares.

### 5.1 `kYR_login` payload (the handshake)

Built in `ngx_xrootd_cms_send_login()` (`src/net/cms/send.c`) in exact
`CmsLoginData` Pup order — **ten tagged scalars, a logical "Fence", then four
bare strings**:

```
  put_short  Version      = 3   (CMS_LOGIN_VERSION)
  put_int    Mode         = kYR_DataServer (0x08) [| kYR_Manager (0x10) if manager_mode]
  put_int    HoldTime     = getpid()
  put_int    tSpace       = total GB
  put_int    fSpace       = free MB           ← capacity the manager balances on
  put_int    mSpace       = min-free MB (100)
  put_short  fsNum        = 1                 (number of filesystems)
  put_short  fsUtil       = utilisation %
  put_short  dPort        = listen_port (root:// data port, e.g. 1094)
  put_short  sPort        = 0
  ── Fence (no bytes on the wire; just the scalar/string boundary) ──
  put_string SID          = "<hostname>:<dport>"   (stable, ~unique node id)
  put_string Paths        = "w /data\nr /atlas"    (see below)
  put_string ifList       = ""  (00 00)
  put_string envCGI       = ""  (00 00)
```

**Mode flags** (`LoginMode` in YProtocol): director `0x1`, manager `0x2`,
peer `0x4`, **server `0x8`**, proxy `0x10`, subman `0x20`. nginx sends
`server` always, and OR-s in the manager bit when `manager_mode` is on so the
parent treats it as a sub-manager rather than a leaf.

**Paths string format.** `xrootd_cms_paths` may carry several colon-separated
namespace prefixes (`/data:/atlas`). `send_login` rewrites them into the real
cmsd form: newline-separated `"<type> <path>"` entries, where `<type>` is `w`
when `allow_write` is set, else `r` (e.g. `"w /data\nw /atlas"`). The length
prefix counts the NUL. A real manager logs this as `adding path: w /…`.

**Space.** `ngx_xrootd_cms_stat_space()` (`src/net/cms/space.c`, via `statvfs`)
fills `tSpace/fSpace/fsUtil`. In **manager mode** these are replaced by
`xrootd_srv_aggregate_space()` so a sub-manager advertises the *sum* of its
children's capacity upward instead of its own (possibly empty) disk.

### 5.2 `kYR_status` — becoming selectable

Immediately after login, `ngx_xrootd_cms_send_status()` sends a **header-only**
frame with `modifier = CMS_ST_RESUME | CMS_ST_NOSTAGE`. This is mandatory: a real
manager keeps a freshly-logged-in node **suspended** until it announces Resume,
and a disk-only node must say `noStage` so the manager never asks it to stage
from tape. Without this frame the node logs in but is never redirected to.

### 5.3 `kYR_load` — periodic heartbeat

`ngx_xrootd_cms_send_load()` runs every `xrootd_cms_interval` seconds. Its
payload is the one place a **bare blob** is used rather than a tagged scalar:

```
  [00 06]              theLoad length = 6   (a bare 2-byte len, NO 0x80 tag!)
  [00 00 00 00 00 00]  6 load bytes: cpu,net,xeq,mem,pag,dsk (0 = idle)
  put_int  dskFree     free MB (tagged int)
```

Emitting `theLoad` as a tagged `put_short` here (instead of a bare length) is
another classic desync: the manager would read the `0x80` tag as the first load
byte and mis-parse `dskFree`. A real manager parses this as `load dlen=13`.

### 5.4 `kYR_space` → `kYR_avail`

When the manager wants an immediate space figure it sends header-only
`kYR_space`; nginx replies `kYR_avail` (`ngx_xrootd_cms_send_avail()`) echoing
the request streamid, payload = `put_int(free_mb) put_int(util_pct)`.

### 5.5 `kYR_ping` → `kYR_pong`

Both header-only. `ngx_xrootd_cms_send_pong()` echoes the streamid. Missing pongs
are how each side detects a dead peer.

### 5.6 `kYR_state` → `kYR_have` — on-demand selection (the subtle one)

Real XRootD managers do **not** redirect purely on the static path list from
login. For each client lookup the manager *verifies the file exists* by
broadcasting `kYR_state` to subscribed servers (`src/net/cms/recv.c`,
`CMS_RR_STATE`):

- `modifier` has `CMS_MOD_RAW` set; the payload is the **raw, NUL-terminated
  namespace path** — **not** Pup-encoded.
- nginx bounds the path length, **rejects any `..` traversal before touching the
  filesystem**, joins it under the export root, and `stat()`s it.
- If present → reply `kYR_have` (`ngx_xrootd_cms_send_have()`), modifier
  `CMS_MOD_RAW | CMS_HAVE_ONLINE`, **echoing the state streamid**, payload = the
  same raw path. If absent → **stay silent** (the manager simply won't select us)
  — exactly matching real cmsd behaviour.

> Note: with a single server exporting `/`, a real manager often redirects on the
> export path without ever sending `kYR_state`; the state→have handler is what
> makes multi-server and cache-miss cases correct.

---

## 6. Negotiation B — nginx as manager (inbound CMS server)

This is the `src/net/cms/server_*.c` half plus the shared-memory
`src/net/manager/registry.c`. Enabled with `xrootd_cms_server on` on a stream server
block listening on the CMS port (e.g. `1213`). Each accepted data-server
connection gets a per-connection `xrootd_cms_srv_ctx_t`
(`src/net/cms/server_handler.c`).

### 6.1 Inbound frame handling

`cms_srv_process_frame()` (`src/net/cms/server_recv.c`) drives the registry:

| Frame in | Action |
|---|---|
| `kYR_login` | parse `CmsLoginData` → `xrootd_srv_register(host, port, paths, free_mb, util_pct)`; mark `logged_in`; arm the per-server ping timer |
| `kYR_load` | extract `dskFree` → `xrootd_srv_update_load()` |
| `kYR_avail` / `kYR_space` | extract `free_mb` + `util_pct` → `xrootd_srv_update_load()` |
| `kYR_pong` | (debug) liveness confirmed |
| `kYR_gone` | `xrootd_srv_unregister_path(host, port, path)` — drop one path, keep the rest of the registration |
| disconnect | `xrootd_srv_close()` → **blacklist host:port for 30 s** then free, so in-flight redirects don't route to a server that just vanished |

The login parser (`cms_srv_parse_login`) is the mirror image of §5.1: it walks
the ten tagged scalars with `tlv_read_next()`, then reads the SID/Paths strings
with `cms_srv_read_string()` (bare `[len][data]`, length includes NUL), strips
the `"<type> "` prefix off each path segment, and stores the bare paths
colon-delimited (`/data:/atlas`) — the exact form `srv_path_matches()` expects.

The manager sends its own `kYR_ping` on a timer (`xrootd_cms_srv_send_ping`,
`src/net/cms/server_send.c`); a failed send closes and unregisters the server.

### 6.2 The registry

`src/net/manager/registry.{h,c}` — a spinlock-protected shared-memory table
(`XROOTD_SRV_REGISTRY_SLOTS = 128` by default, tunable via
`xrootd_registry_slots`) so **every nginx worker shares one view**. Each slot
holds host, port, colon-delimited export paths, `free_mb`, `util_pct`,
`last_seen`, a blacklist deadline, and health-check fields.

Selection (`xrootd_srv_select`):

- **longest-prefix match** over each colon-delimited path token,
- **reads** → server with the lowest `util_pct`,
- **writes** → server with the most `free_mb`,
- blacklisted / drained entries are skipped.

`xrootd_srv_locate_all()` builds a multi-server `kXR_locate` body
(`S<r|w>host:port …`). A full table drops new registrations with a `WARN` and
bumps the `xrootd_registry_full_total` Prometheus counter.

---

## 7. Negotiation C — manager ↔ `root://` client (the redirect)

This is where CMS meets the data protocol. A `root://` client never speaks CMS;
it speaks `kXR_locate` / `kXR_open` on the data port, and the manager answers
with `kXR_redirect`. The lookup order, when `xrootd_manager_mode on`
(`src/protocols/root/read/locate.c`, `src/protocols/root/read/open.c`):

1. **Redirect-collapse cache** (`src/net/manager/redir_cache.c`) — if
   `xrootd_collapse_redir` is on and a recent identical lookup is cached, answer
   immediately, skipping CMS entirely. TTL = `xrootd_collapse_redir_ttl`.
2. **Live registry** — `xrootd_srv_select(path, for_write)`.
3. **Static map** — `xrootd_manager_map` fallback (see manager-mode.md).
4. **CMS escalation** (sub-manager only) — ask the *parent* (§7.1).
5. Otherwise `kXR_notFound` / serve locally.

### 7.1 The pending-locate bridge (sub-manager escalation)

When a sub-manager misses locally it must ask its parent over CMS and hold the
client's `root://` session open until the answer arrives. This couples two
different connections — a data-channel client and the CMS control channel —
which is the hard part. The mechanism (`src/net/manager/pending.c` +
`src/net/cms/recv.c`):

```
 client kXR_locate /f  ─►  sub-manager (data channel, worker W)
                            │  registry miss
                            │  streamid = next_streamid()
                            │  ngx_xrootd_cms_send_locate(streamid, "/f") ─► parent (CMS, worker W)
                            │  xrootd_pending_insert(streamid, pid, client_fd, …)
                            │  ctx->state = XRD_ST_WAITING_CMS
                            │  arm read timer (xrootd_cms_locate_timeout, default 5 s)
                            ▼
 parent kYR_select host:port (echoes streamid) ─► sub-manager (CMS, worker W)
                            │  cms_wake_pending_session():
                            │    xrootd_pending_lookup(streamid, pid)
                            │    resolve client_fd → live ngx_connection_t
                            │    state == XRD_ST_WAITING_CMS ?
                            │    xrootd_send_redirect(host, port)
                            ▼
 client  ◄── kXR_redirect host:port ──  then connects there for the data
```

Why this works without cross-worker IPC: **each worker has its own CMS
connection** (§8), so the `kYR_select` reply lands on the *same* worker event
loop that holds the suspended client. `streamid` is correlated together with the
**worker pid** (two workers can independently reuse the same streamid value), and
the wake path validates `client_conn->number`/`fd` to detect an fd that was
recycled after the client disconnected.

`kYR_try` (opcode 24) is handled identically but carries an *ordered list* of
`host:port` alternatives; nginx wakes the session on the **first** entry and the
client falls back to later entries itself if it can't reach it. On timeout the
client gets `kXR_wait 5` (retry shortly) rather than an error.

`kYR_status` from the parent toggles `conf->cms_suspended`, which gates new
client logins during a managed drain.

---

## 8. Non-obvious implementation details (wire-compliance gotchas)

A condensed list of the things that are easy to get wrong, each of which was a
real interop failure against a real `cmsd`:

1. **Pup strings carry no tag byte.** `[2-byte len][data + NUL]`, length includes
   the NUL; empty/NULL = `00 00`. Scalars *do* carry a `0x80`/`0xa0` tag. Putting
   a tag on a string (or omitting trailing strings) makes the real parser report
   *"invalid login data."* (`ngx_xrootd_cms_put_string`, `cms_srv_read_string`.)

2. **`kYR_load`'s `theLoad` is a bare blob, not a tagged short.** `[00 06][6
   bytes]` then a tagged `put_int` for `dskFree`. A `put_short` here desyncs the
   whole frame. (`ngx_xrootd_cms_send_load`.)

3. **Status bits are `Stage=0x01, noStage=0x02, Resume=0x04, Suspend=0x08,
   Reset=0x10`.** The original nginx constants had `SUSPEND=0x01`/`RESUME=0x02`,
   which silently kept nodes suspended. Send `Resume|noStage` *after* login or you
   never get selected.

4. **`kYR_state`/`kYR_have` are RAW, not Pup.** The path is a plain
   NUL-terminated string with `modifier` carrying `CMS_MOD_RAW`; the reply must
   set `CMS_MOD_RAW | CMS_HAVE_ONLINE` and **echo the request streamid**. Treating
   the path as a Pup string corrupts the lookup.

5. **Selection is on-demand, not static.** Registering paths at login is *not*
   sufficient for a real manager — it verifies per file via `kYR_state` → expects
   `kYR_have`. Answer only for files that actually `stat()` on disk; stay silent
   otherwise. Reject `..` *before* the `stat()`.

6. **One CMS connection per nginx worker.** Each worker's `init_process` hook
   calls `ngx_xrootd_cms_start()` independently; the master never connects. This
   is deliberate — it makes the parent's `kYR_select` land on the same worker that
   holds the suspended client (§7.1), eliminating all cross-worker IPC for the
   pending-locate bridge. It does mean the parent sees N connections from one node
   (one per worker).

7. **Blacklist-on-disconnect.** When a data server drops, the manager doesn't just
   free the slot — it blacklists `host:port` for 30 s so redirect responses
   already in flight don't send a client to a corpse. A clean reconnect+heartbeat
   clears it.

8. **Aggregate space upward in manager mode.** A sub-manager's `kYR_login` and
   `kYR_load` report `xrootd_srv_aggregate_space()` (sum of children's `free_mb`,
   mean `util_pct`), not its own disk — so the parent balances on real downstream
   capacity. The `kYR_Manager` mode bit is OR-ed into the login so the parent
   knows it's a sub-manager.

9. **`streamid` discipline.** `0` for unsolicited heartbeat frames; **echo** the
   request streamid on every reply (`pong`, `avail`, `have`). The sub-manager's
   outbound `kYR_locate` uses a per-worker monotonic counter
   (`ngx_xrootd_cms_next_streamid`, wraps `UINT32_MAX → 1`) as the correlation
   key for the pending table.

10. **Frame hygiene.** All header/scalar fields are big-endian via the `wire.c`
    helpers — never raw casts. `dlen + 8 > 4096` ⇒ drop the connection. The reader
    accumulates into a fixed `inbuf` and only dispatches a *complete* frame, so a
    partial read across event ticks is safe.

---

## 9. Configuration directives

| Directive | Block | Default | Purpose |
|---|---|---|---|
| `xrootd_cms_manager host:port` | stream server | — | upstream manager to register with (enables the CMS client) |
| `xrootd_cms_paths /a:/b` | stream server | export root | namespace prefixes to advertise in `kYR_login` |
| `xrootd_cms_interval secs` | stream server | 30 | `kYR_load` heartbeat period |
| `xrootd_cms_server on` | stream server | off | accept inbound data-server CMS registrations (enables the CMS server / manager listener) |
| `xrootd_manager_mode on` | stream server | off | turn `kXR_locate`/`kXR_open` into registry-driven redirects |
| `xrootd_registry_slots N` | stream server | 128 | server-registry capacity |
| `xrootd_cms_locate_timeout time` | stream server | 5s | how long to hold a client while escalating via CMS (§7.1) |

### 9.1 Network-fault resilience (phase-50)

These deadlines/caps harden the CMS connection against timeouts, packet loss,
half-open/slowloris peers, and hostile managers/nodes **with no wire change**.
Defaults are ON but generous (derived from the heartbeat interval), so a
conformant cmsd/data-node is never tripped; set a timeout/cap to `0` to disable.
See [docs/refactor/phase-50-cms-protocol-hardening.md](../refactor/phase-50-cms-protocol-hardening.md).

| Directive | Block | Default | Purpose |
|---|---|---|---|
| `xrootd_cms_read_timeout time` | stream server (client) | `max(3×interval, 90s)` | reconnect if the manager goes silent this long (detects black-holed/half-open managers) |
| `xrootd_cms_send_timeout time` | stream server (client) | 10s | connect + first-write readiness window for the manager socket |
| `xrootd_cms_initial_delay time` | stream server (client) | 0 (loopback) / 10ms | delay before the **first** connect attempt at worker start (see fast cold-start settling below) |
| `xrootd_cms_connect_retry time` | stream server (client) | 10ms (loopback) / 75ms | retry interval while the manager is not yet listening, during the cold-start fast-retry window |
| `xrootd_cms_tcp_keepalive on\|off` | stream server (client) | on | `SO_KEEPALIVE` + tight probes on the manager socket |
| `xrootd_cms_tcp_user_timeout time` | stream server (client) | = read timeout | `TCP_USER_TIMEOUT` kernel backstop on the manager socket |
| `xrootd_cms_server_login_timeout time` | stream server (manager) | 10s | close a peer that never completes LOGIN (+sss xauth) — anti-slowloris |
| `xrootd_cms_server_idle_timeout time` | stream server (manager) | `max(3×interval, 90s)` | close + unregister a logged-in node that goes silent this long |
| `xrootd_cms_server_max_connections N` | stream server (manager) | 4096 | per-worker cap on accepted CMS connections (`0` = unlimited) |
| `xrootd_cms_server_tcp_keepalive on\|off` | stream server (manager) | on | `SO_KEEPALIVE` + tight probes on accepted sockets |
| `xrootd_cms_server_tcp_user_timeout time` | stream server (manager) | = idle timeout | `TCP_USER_TIMEOUT` kernel backstop on accepted sockets |

A **leaf data server** sets `xrootd_cms_manager` (+ optional `xrootd_cms_paths`).
A **manager** sets `xrootd_cms_server on` + `xrootd_manager_mode on`. A
**sub-manager** sets all of the above. See
[Hierarchical Cluster](../05-operations/hierarchical-cluster.md) for full
three-tier configs.

---

## 10. Source-file map

| File | Responsibility |
|---|---|
| `src/net/cms/cms_internal.h` | opcode/modifier constants, `ngx_xrootd_cms_ctx_t`, prototypes |
| `src/net/cms/connect.c` | CMS-client lifecycle: connect, login→status→load, heartbeat timer, backoff |
| `src/net/cms/send.c` | outbound client frames: login, status, load, avail, pong, locate, have |
| `src/net/cms/recv.c` | inbound manager frames at a node: ping→pong, space→avail, status, state→have, select/try→wake |
| `src/net/cms/wire.c` | big-endian + XrdOucPup encode/decode helpers |
| `src/net/cms/space.c` | `statvfs` space measurement; export-path selection |
| `src/net/cms/server_handler.c` | accept an inbound data-server connection |
| `src/net/cms/server_recv.c` | parse login/load/avail/gone; drive the registry |
| `src/net/cms/server_send.c` | outbound manager frames (ping) |
| `src/net/manager/registry.c` | shared-memory server registry + selection |
| `src/net/manager/redir_cache.c` | redirect-collapse cache |
| `src/net/manager/pending.c` | pending-locate bridge (suspend client ↔ CMS reply) |
| `src/protocols/root/read/locate.c`, `src/protocols/root/read/open.c` | client-facing redirect / CMS-escalate logic |

---

## 11. Debugging a CMS exchange

```bash
# Watch the CMS handshake from the nginx side
error_log /tmp/xrd-test/logs/debug.log debug;   # in the stream server block

# Look for, in order:
#   "CMS heartbeat starting for manager <host:port>"
#   "CMS login sent to <host:port>"
#   "CMS server: registered <host>:<port> paths=[…] free_mb=… util_pct=…"   (manager side)

# Confirm the data port is reachable and the CMS port is listening
ss -tlnp | grep -E '1094|1213'

# End-to-end: a locate against the manager should redirect, not serve
xrdfs <manager-host>:1094 locate /data/file
```

Against a **real `cmsd`**: a successful registration appears in the manager log
as `server.<pid>@<host>:<dport>`, the load frame parses as `load dlen=13`, and
`xrdfs <mgr> locate /f` redirects to the nginx node. See the
[Hierarchical Cluster](../05-operations/hierarchical-cluster.md) test section for
the known-good mixed real-cmsd / nginx harness.

---

## See also

- [Cluster Management](../05-operations/cluster-management.md) — operational architecture, M1–M5 phases.
- [Hierarchical Cluster](../05-operations/hierarchical-cluster.md) — multi-tier topology, escalation, and the select-then-proxy extension.
- [Manager Mode](../05-operations/manager-mode.md) — static `xrootd_manager_map`.
- [XRootD Client Interaction](xrootd-client-interaction.md) — what `xrdcp`/`xrdfs` do on the `root://` data channel.
- [Protocol Notes](../10-reference/protocol-notes.md) — `root://` wire-structure details.
