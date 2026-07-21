# Phase 34 — Packet Marking / SciTags (network flow tagging)

**Status:** ✅ Implemented / as-built reference (source: `src/observability/pmark/`)
**Author:** design doc retained as implementation rationale and upstream-source audit
**Scope:** add XRootD-compatible *packet marking* (the SciTags initiative) to nginx-xrootd,
configurable from `nginx.conf` in the same spirit as XRootD's `pmark` directive. **Both** SciTags
techniques are REQUIRED deliverables: (a) the **Firefly UDP** reporting path (for byte-for-byte
XRootD interop) **and** (b) the **IPv6 Flow Label** marking path — the latter *completes the
TODO stub XRootD never finished* (see §1 and the full spec in §6.4). Flow-label marking is
mandatory, not an optional add-on.
**Reference implementation studied:** `/tmp/xrootd-src/src/XrdNet/XrdNetPMark*.{cc,hh}` and
`/tmp/xrootd-src/src/XrdHttpTpc/XrdHttpTpcPMarkManager.{cc,hh}` (read in full for this plan).

**Current implementation note (2026-06-14):** the plan has landed under
`src/observability/pmark/`. `firefly.c` emits start/ongoing/end lifecycle datagrams,
`flowlabel.c` applies Linux IPv6 flow labels with a fail-open capability probe,
and `config.c`/`mapping.c` implement the nginx directives and SciTags mapping
rules. Keep the sections below as the source-verified rationale, not as a
future TODO list.

**Update (2026-07-21, phase-88 loose-end closure):** the "ongoing" echo timer
(`brix_pmark_echo`, D4/§ timer in `firefly.c`) had been implemented from the
start — the only genuinely missing piece was the **min-30s clamp** the table
below specifies (`ffecho <sec>` min 30). That clamp now exists in `config.c`
(values 1..29999ms are raised to 30s with a config warning; `0`/unset stays
off) and is covered by 3 tests in `tests/test_pmark.py`. Note the table rows
below describe *stock XRootD* behavior, where ffecho is parsed but its refresh
thread is commented out — "unimplemented" there refers to XRootD, not brix.

---

## 1. What this is and why

**SciTags** ("Scientific Network Tags", scitags.org / the WLCG–ESnet–GÉANT Research Networking
Technical WG) lets a storage endpoint label each network flow with **which experiment** and
**which activity** (data movement type) the flow belongs to, so network operators can account
for and engineer R&E traffic per-VO/per-activity. A flow is tagged with a 16-bit **flow-id**:

```
flow-id (16 bits)  =  (experiment-id << 6) | activity-id
                      └── 10 bits, 1..1023 ──┘ └ 6 bits, 1..63 ┘
```

SciTags defines **two** marking techniques:

1. **Flow Label marking** — stamp the flow-id into the IPv6 packet header's 20-bit *Flow Label*
   (RFC 6437). In-band, per-packet, IPv6-only.
2. **Firefly / packet marking (UDP reporting)** — emit out-of-band UDP "firefly" datagrams
   (RFC 5424-syslog-wrapped JSON) describing each flow's lifecycle (start/ongoing/end) to a
   collector (the `flowd` daemon, default UDP port **10514**). Works on IPv4 and IPv6.

> **Critical fact discovered while reading the XRootD source:** XRootD ships **only the Firefly
> path**. The IPv6 flow-label path is a **TODO stub** — `useFLbl`/`addFLFF` are parsed and stored
> (`XrdNetPMarkCfg.cc:139,141,1193-1196`), but the actual marking site is an **empty commented-out
> block** — verbatim:
> ```
> // if (useFLbl && addrInfo.isIPType(XrdNetAddrInfo::IPv6) && !addrInfo.isMapped())
> //    { TODO??? }
> ```
> (`XrdNetPMarkCfg.cc:240-248`) — there is **no** `setsockopt(IPV6_FLOWLABEL_MGR/IPV6_FLOWINFO)`
> anywhere in the XRootD tree. The periodic "ongoing" echo (`ffecho`) is likewise parsed but its
> refresh thread is commented out (`XrdNetPMarkFF.cc:129-138, 260-265`).
>
> **This plan REQUIRES both paths.** Firefly gives byte-for-byte XRootD interop; the IPv6
> flow-label path **implements what XRootD only stubbed** (`useFLbl` gating, IPv6-only,
> non-mapped) with the real Linux kernel calls XRootD never wrote. Because XRootD provides no
> reference encoding or syscalls for the label, §6.4 specifies them in full and pins the bit
> layout to the SciTags Flow Label specification.

Goal: a HEP site can drop nginx-xrootd in place of an XRootD gateway and its flows show up in
the same SciTags/flowd dashboards, configured the same way — **and**, unlike stock XRootD, its
IPv6 data flows are additionally stamped in-band with the SciTags flow label.

---

## 2. Ground truth — how XRootD's `pmark` works (with file:line)

### 2.1 Flow-id encoding (`XrdNetPMark.{hh,cc}`)
- Constants `XrdNetPMark.hh:89-99`: `minTotID=65`, `maxTotID=65535`, `btsActID=6`,
  `mskActID=63`. Derived: `minExpID=1`, `maxExpID=1023`, `minActID=1`, `maxActID=63`.
- `XrdNetPMark::getEA(cgi, &ec, &ac)` (`XrdNetPMark.cc:40-66`): parse `scitag.flow=<N>` from a
  CGI/opaque string; if `65 <= N <= 65535` then `ec = N >> 6; ac = N & 0x3F;` else both 0.
- `Handle` (`XrdNetPMark.hh:40-70`): flyweight `{appName, eCode, aCode}`. `Valid()` =
  `(ec==0 && ac==0)` *or* both in range. (The all-zero case is the "no tag" HTTP-TPC sentinel.)

### 2.2 Code determination priority (`getCodes`, `XrdNetPMarkCfg.cc:774-843`)
For each transfer the (experiment, activity) pair is resolved in this order:
1. **`scitag.flow` in the request CGI** → `getEA()` (client-supplied wins).
2. **path pattern** → `p2eMap` (glob match, `XrdOucMapP2X`).
3. **VO** (`client.vorg`, first token) → `v2eMap`.
4. **default experiment** `expDflt`.
Then activity: **user** map → **role** map → per-experiment **default activity** → `1`.

### 2.3 Firefly wire format (interop-critical — `XrdNetPMarkFF.cc:60-99`)
Exact template (verbatim from source; `%%` are second-pass substitutions):
```
<134>1 - <host> xrootd - firefly-json - {
  "version":1,
  "flow-lifecycle":{ "state":"start|ongoing|end",
     "current-time":"yyyy-mm-ddThh:mm:ss.uuuuuu+00:00",
     "start-time":"<iso8601>" [,"end-time":"<iso8601>"] },
  "usage":{"received":<u64>,"sent":<u64>},
  "netlink":{"rtt":<sec>.<ms3>},
  "context":{ "experiment-id":<int>, "activity-id":<int> [,"application":"<app>"] },
  "flow-id":{ "afi":"ipv4|ipv6", "src-ip":"<ip>", "dst-ip":"<ip>",
              "protocol":"tcp", "src-port":<int>, "dst-port":<int> }
}
```
- `<134>1` = RFC 5424 PRI(=local0.info)+version. `experiment-id`/`activity-id` are **decimal
  integers, NOT the packed flow-id** (the firefly carries the split fields).
- **PUT convention** (`XrdNetPMarkFF.cc:158-160, 411-416`): for uploads the *client* is `src`
  and received/sent byte counts are swapped so "supplier is source".
- Emitted on `Start()` (state=start, `XrdNetPMarkFF.cc:432`) and in the destructor (state=end,
  `:271-289`). No periodic "ongoing" in the shipped build.

### 2.4 Stats (`SockStats`, `XrdNetPMarkFF.cc:299-322`)
Linux-only `getsockopt(fd, IPPROTO_TCP, TCP_INFO)` → `tcpi_bytes_received`, `tcpi_bytes_acked`,
`tcpi_rtt`. Non-Linux → zeros. (Maps directly to nginx since we are Linux-only in practice.)

### 2.5 Config grammar (`XrdNetPMarkCfg.cc:974-1214`)
`pmark` sub-keywords and defaults:

| `pmark` sub-directive | Meaning | Default |
|---|---|---|
| `defsfile [fail\|nofail] {<path> \| {curl\|wget} [tmo] <url>}` | scitags experiment/activity JSON registry | none; `nofail`, tmo 30s |
| `domain {any\|local\|remote}` | only mark flows of this address class | `remote` |
| `ffdest {origin[:port] \| host[:port]}[,…]` | firefly collector(s); presence ⇒ firefly on | port `10514` |
| `ffecho <sec>` | periodic "ongoing" interval (min 30) | 0 (off; unimplemented) |
| `map2exp {default \| path <p> \| vo <v>} <expName>` | path/VO→experiment | — |
| `map2act <expName> {default \| role <r> \| user <u>} <actName>` | role/user→activity | act `1` |
| `use [no]flowlabel \| [no]firefly \| [no]scitag` | enable modes | scitag on, firefly auto, flowlabel off |
| `debug\|nodebug`, `trace\|notrace` | logging | off |

- **Opt-in**: nothing marks unless `use firefly`/`ffdest`/`ffecho` is present (`Config()` auto at
  `:298-308`). `defsfile` is *mandatory* iff any `map2exp/map2act` is declared (`:322-327`).
- `defsfile` JSON schema (`LoadJson`, `:891-966`):
  `{"modified":<date>, "experiments":[{"expName":str,"expId":int,
  "activities":[{"activityName":str,"activityId":int},…]},…]}`.

### 2.6 Where XRootD hooks it in (`AREA[integration]`)
- **root://** — begins on **file OPEN** (`XrdXrootdXeq.cc:1756-1776`): one `Handle` per
  connection (`pmHandle`, `pmDone`), extended to bound child streams 1..15
  (`XrdXrootdXeq.cc:339-345`). All read/write inherit it; no per-op Begin.
- **HTTP plain GET/PUT** — **not marked**. Only the `SciTag:` header is parsed
  (`XrdHttpReq.cc:207-273`) into CGI `scitag.flow` + `pmark.appname`.
- **HTTP-TPC** — `XrdHttpTpcPMarkManager` marks each **outbound libcurl** socket via
  `CURLOPT_OPENSOCKETFUNCTION`/`CLOSESOCKETFUNCTION` (`XrdHttpTpcTPC.cc:120-175, 936-940`):
  `startTransfer()` arms it, `beginPMarks()` creates a handle per captured fd after
  `curl_multi_perform`, `endPmark(fd)` emits the end-firefly **before** `close(fd)`. PULL uses
  `appname=http-put`, PUSH uses `http-get` (supplier-is-source).

---

## 3. Architecture mapping to nginx-xrootd

nginx is a single-threaded **event loop per worker** (no XRootD thread model). This is actually
*simpler* for Firefly, because UDP emission is fire-and-forget:

| XRootD construct | nginx-xrootd equivalent |
|---|---|
| global `XrdNetPMark` singleton | per-worker `xrootd_pmark_t` built from merged srv conf at worker init |
| `XrdNetMsg` UDP sender (collector/origin) | one **non-blocking `AF_INET/INET6` UDP socket per worker** (`ngx_socket`/`sendto`), created in the module's init-process hook |
| `Handle` / `XrdNetPMarkFF` per transfer | `xrootd_pmark_flow_t` allocated on the connection pool (root://) or per-TPC-stream |
| background `Refresh` thread (disabled) | optional `ngx_event` **timer** that walks active flows for "ongoing" echo — event-loop native, no thread |
| `getsockopt(TCP_INFO)` | identical syscall on `c->fd` / curl fd |
| defsfile fetch via curl/wget subprocess | parse a local JSON file with **jansson** (already linked, see `phase-10`); optional URL fetch deferred |

Because emission is non-blocking `sendto` to a UDP socket, **no thread pool and no blocking I/O
are introduced on the event loop**. A failed/queued `sendto` (EAGAIN) is dropped (matching
XRootD's fire-and-forget), counted in a metric.

---

## 4. Configuration design (nginx idiom, mirrors `pmark`)

Keep the existing flat `xrootd_*` directive convention (see `src/protocols/root/stream/module.c` command
table). Directives are **per-server** (`NGX_STREAM_SRV_CONF` + matching HTTP `SRV/LOC`), so
each `server {}` can have its own SciTags policy — consistent with cache/upstream/proxy.

```nginx
# --- master switch + transport (mirrors `pmark use` / `ffdest`) ---
xrootd_pmark            on;                 # off by default (opt-in, like XRootD)
xrootd_pmark_firefly    on;                 # emit firefly UDP (default on when pmark on)
xrootd_pmark_flowlabel  on;                 # REQUIRED path: stamp IPv6 flow label (default on,
                                            #   auto no-op on IPv4 / mapped addrs); see §6.4
xrootd_pmark_scitag_cgi on;                 # honor client scitag.flow / SciTag: header

xrootd_pmark_firefly_dest   flowd.example.org:10514;   # ffdest (repeatable)
xrootd_pmark_firefly_origin on;                        # also report to client origin:10514
xrootd_pmark_echo           60s;                        # ffecho (>=30s; 0/unset = off)
xrootd_pmark_domain         remote;                     # any|local|remote (default remote)
xrootd_pmark_appname        nginx-xrootd;               # firefly context.application

# --- experiment/activity registry (defsfile) ---
xrootd_pmark_defsfile  /etc/xrootd/scitags.json;        # local scitags registry (jansson)
# xrootd_pmark_defsfile_url curl 30s https://www.scitags.org/api.json;  # phase 2 (optional)

# --- mappings (repeatable; mirror map2exp / map2act) ---
xrootd_pmark_map_experiment vo    atlas      atlas;     # VO atlas        -> experiment "atlas"
xrootd_pmark_map_experiment path  /cms/*     cms;       # path glob       -> experiment "cms"
xrootd_pmark_map_experiment default           dteam;    # fallback experiment
xrootd_pmark_map_activity   atlas default      default; # per-exp default activity
xrootd_pmark_map_activity   atlas role production write_production;
xrootd_pmark_map_activity   cms   user prod-svc staging;
```

Equivalence to XRootD: `xrootd_pmark_firefly_dest` ≡ `pmark ffdest`,
`xrootd_pmark_map_experiment` ≡ `pmark map2exp`, `xrootd_pmark_map_activity` ≡ `pmark map2act`,
`xrootd_pmark_echo` ≡ `pmark ffecho`, `xrootd_pmark_domain` ≡ `pmark domain`,
`xrootd_pmark_scitag_cgi` ≡ `pmark use scitag`, `xrootd_pmark_flowlabel` ≡ `pmark use flowlabel`.

**Conf fields** (new, in `ngx_stream_xrootd_srv_conf_t` at `src/core/types/config.h`, and mirrored
in the WebDAV/S3 loc confs):
```c
ngx_flag_t    pmark_enable;          /* NGX_CONF_UNSET */
ngx_flag_t    pmark_firefly;         /* NGX_CONF_UNSET */
ngx_flag_t    pmark_flowlabel;       /* NGX_CONF_UNSET */
ngx_flag_t    pmark_scitag_cgi;      /* NGX_CONF_UNSET */
ngx_flag_t    pmark_firefly_origin;  /* NGX_CONF_UNSET */
ngx_array_t  *pmark_firefly_dest;    /* of xrootd_pmark_dest_t {addr, port} */
ngx_msec_t    pmark_echo;            /* 0 = off; clamp >=30s */
ngx_uint_t    pmark_domain;          /* enum any|local|remote */
ngx_str_t     pmark_appname;
ngx_str_t     pmark_defsfile;
ngx_array_t  *pmark_exp_rules;       /* of xrootd_pmark_exp_rule_t */
ngx_array_t  *pmark_act_rules;       /* of xrootd_pmark_act_rule_t */
```
Standard `merge_*_conf()` handling (main→srv→loc), `NGX_CONF_UNSET` defaults. No `./configure`
needed for the directives themselves — only for the new `.c` files (§6).

---

## 5. New subsystem layout: `src/observability/pmark/`

Following the per-subfolder convention (README + WHAT/WHY/HOW headers per file):

| File | Responsibility |
|---|---|
| `src/observability/pmark/pmark.h` | public types (`xrootd_pmark_t`, `xrootd_pmark_flow_t`, code constants) + API prototypes |
| `src/observability/pmark/scitag.c` | flow-id encode/decode (`(exp<<6)\|act`, range checks), `scitag.flow` CGI / `SciTag:` header parse — the analogue of `XrdNetPMark::getEA` |
| `src/observability/pmark/defsfile.c` | parse the scitags registry JSON (jansson) → experiment/activity name→id maps |
| `src/observability/pmark/mapping.c` | `getCodes()` analogue: resolve (exp,act) from scitag → path → VO → default, and activity from user→role→default |
| `src/observability/pmark/firefly.c` | per-worker UDP socket; build the RFC5424+JSON datagram (template §2.3 verbatim); non-blocking `sendto` to each dest + origin; `flow_begin`/`flow_end`/`flow_echo` |
| `src/observability/pmark/sockstats.c` | `getsockopt(TCP_INFO)` → bytes/rtt; ISO-8601 UTC timestamp helper |
| `src/observability/pmark/flowlabel.c` | **REQUIRED**: stamp the 20-bit IPv6 flow label via `setsockopt(IPV6_FLOWLABEL_MGR)` + `IPV6_FLOWINFO_SEND` (inbound) and `sin6_flowinfo` at connect (outbound) — the path XRootD left as `TODO???`; auto no-op on IPv4 / mapped addrs. Full spec in §6.4 |
| `src/observability/pmark/config.c` | directive setters + merge + worker-init build of `xrootd_pmark_t` |
| `src/observability/pmark/README.md` | subsystem doc |

All new `.c` files must be registered in the repo-root **`config`** script (`ngx_module_srcs`)
and a single `./configure --add-module=$REPO && make` run (build governance, CLAUDE.md).

### 5.1 Core data flow
```
request/connection
  └─ identity ready (post-auth) ──► mapping.c getCodes(identity, path, cgi)
                                       │  (scitag.flow ▸ path ▸ VO ▸ default)
                                       ▼
                                   (exp, act) valid?
                          ┌────────────┴─────────────┐
                          ▼                            ▼
                 firefly.c flow_begin            flowlabel.c (REQUIRED, IPv6 only)
                 (build JSON, sendto)            setsockopt(fd, IPV6_FLOWLABEL_MGR)
                          │
              (echo timer, optional)  ── periodic "ongoing" ──┐
                          │                                     │
              transfer/connection end ──► firefly.c flow_end (state=end, TCP_INFO bytes)
```

---

## 6. Per-protocol integration (with our file:line anchors)

### 6.1 root:// (stream) — primary
- **Where:** mirror XRootD "begin on open". Hook in `src/protocols/root/read/open_request.c` (`xrootd_handle_open`,
  ~`:140`) **after** the auth gate, where path + `ctx->identity` + `is_write` are known.
- Store `xrootd_pmark_flow_t *pmark_flow` on `xrootd_ctx_t` (`src/core/types/context.h:142` area) plus a
  `pmark_done` flag (one flow per connection, like XRootD's `pmHandle`/`pmDone`).
- **fd:** `c->fd` directly. **activity:** read vs write from the open mode; map via `mapping.c`.
- **Identity timing gotcha** (from research): identity is only complete post-`kXR_auth`; do not
  mark during handshake. Open is always post-auth, so opening is the correct, safe hook.
- **Bound secondaries** (`kXR_bind`, `src/protocols/root/session/` + `context.h:382-384`): a bound data channel
  should inherit the primary's (exp,act) and emit its own firefly for its own `c->fd` — analogue
  of XRootD extending the handle to child streams.
- **End:** `src/protocols/root/connection/disconnect.c` (`xrootd_on_disconnect`) → `firefly.c flow_end` (read
  final TCP_INFO before nginx closes the fd).
- `scitag.flow` arrives in the kXR_open **opaque/CGI** (`?scitag.flow=N`) — parse in `scitag.c`.

### 6.2 WebDAV / S3 (HTTP)
- **Plain GET/PUT:** XRootD does **not** mark these. We have a choice (decision D1, §9): match
  XRootD (only TPC) *or* extend to plain HTTP transfers (we already have a clean post-auth point).
  Recommended: **make it configurable** — default to TPC-only for strict interop, with
  `xrootd_pmark_http_plain on;` to also mark plain GET/PUT (a documented superset).
- **`SciTag:` request header** → CGI `scitag.flow` (XrdHttp parses a header; we do the same in
  `scitag.c`, called from `src/protocols/webdav/dispatch.c:24` / `src/protocols/s3/handler.c:24`). fd = `r->connection->fd`.
- Identity from `webdav/auth_cert.c` / `auth_token.c` / `s3/auth_sigv4_verify.c`.

### 6.3 TPC (outbound — the most XRootD-faithful path)
- **Native TPC** (`src/tpc/outbound/connect.c:82-139`): we already `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)`
  right after `socket(2)` — add the **flow-label setsockopt** and register the fd with `firefly.c`
  at the same site (`flow_begin` after connect succeeds; `flow_end` on teardown). Source identity
  parsed from the TPC URL/params (`src/tpc/engine/launch.c`).
- **WebDAV TPC (libcurl)** (`src/protocols/webdav/tpc_curl.c:110`): we already set `CURLOPT_RESOLVE`. Add
  `CURLOPT_OPENSOCKETFUNCTION` + `CURLOPT_CLOSESOCKETFUNCTION` exactly like
  `XrdHttpTpcPMarkManager`: open-cb captures the curl fd → `flow_begin`; close-cb → `flow_end`
  **before** `close(fd)` (so TCP_INFO byte counts are non-zero). PULL ⇒ `appname=http-put`,
  PUSH ⇒ `appname=http-get` (supplier-is-source). Confirm curl ≥ 7.21.7 for opensocket cb.

### 6.4 IPv6 Flow Label marking — REQUIRED implementation (completes XRootD's `TODO???`)

This is the mechanism XRootD declared (`useFLbl`) but never wrote (`XrdNetPMarkCfg.cc:240-248`).
`src/observability/pmark/flowlabel.c` MUST implement it for real. It stamps the SciTags flow-id into the
20-bit IPv6 Flow Label of every data packet of a flow, in-band (no collector required), so that
routers/NRENs can classify traffic without seeing firefly. It is applied to **the same sockets**
firefly reports on, at the same begin sites (§6.1–6.3), in addition to firefly.

**Applicability gate (mirrors XRootD's intended condition, now enforced):**
mark the label only when `pmark_flowlabel` is on AND the socket's peer is genuine IPv6 AND not an
IPv4-mapped address (`::ffff:a.b.c.d`). On IPv4 / mapped / unknown-family, `flowlabel.c` is a
silent no-op (firefly still runs). This is exactly XRootD's `addrInfo.isIPType(IPv6) && !isMapped()`.

**Encoding — `scitag_flowlabel_encode(exp, act) → uint32_t` (single source of truth):**
the SciTags Flow Label spec carries the 16-bit flow-id inside the 20-bit label. Pin the layout in
ONE function so it can track the normative SciTags spec version:
```c
/* 20-bit IPv6 flow label (RFC 6437). SciTags flow-id = (exp<<6)|act occupies the low 16 bits;
 * the top 4 bits are a version/marker nibble so collectors can recognise a SciTags-tagged flow.
 * NOTE: the exact placement MUST match the SciTags "Flow Label Marking" spec version deployed at
 * the site — keep it here and nowhere else. */
#define XRD_PMARK_FL_MASK     0x000FFFFFu          /* 20 bits */
#define XRD_PMARK_FL_VERSION  0x1u                 /* high nibble marker; spec-defined */
static ngx_inline uint32_t
scitag_flowlabel_encode(uint16_t exp, uint16_t act)
{
    uint32_t flowid = ((uint32_t)(exp & 0x3FF) << 6) | (act & 0x3F);   /* 16-bit scitags flow-id */
    return ((XRD_PMARK_FL_VERSION << 16) | flowid) & XRD_PMARK_FL_MASK;
}
```
(`IPV6_FLOWLABEL_MASK` is not exported by glibc on this host — define `XRD_PMARK_FL_MASK`
ourselves, as above.)

**Linux kernel calls — two cases (both REQUIRED):**

*(a) Inbound accepted sockets — the data-heavy direction for root:// GET and WebDAV/S3 download.*
We cannot re-`connect()` an accepted fd, so reserve+associate the label with the connected peer
via the flow-label manager, then enable send:
```c
#include <linux/in6.h>      /* struct in6_flowlabel_req, IPV6_FLOWLABEL_MGR, IPV6_FL_* */
#include <netinet/in.h>     /* IPV6_FLOWINFO_SEND */

/* peer6 = the connected peer's struct in6_addr (from c->sockaddr / getpeername). */
struct in6_flowlabel_req fl;
ngx_memzero(&fl, sizeof(fl));
fl.flr_dst    = peer6;
fl.flr_label  = htonl(scitag_flowlabel_encode(exp, act));   /* network byte order, masked */
fl.flr_action = IPV6_FL_A_GET;
fl.flr_flags  = IPV6_FL_F_CREATE;       /* create the lease if absent */
fl.flr_share  = IPV6_FL_S_EXCL;         /* exclusive to this socket */
if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &fl, sizeof(fl)) == 0) {
    int on = 1;
    (void) setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on));
    /* metric: pmark_flowlabel_set++ */
} else {
    /* fail-open: log once at WARN, metric pmark_flowlabel_failed++, continue (firefly still on) */
}
```

*(b) Outbound sockets we create — native TPC (`src/tpc/outbound/connect.c`).*
Simplest path: set the label in the destination `sockaddr_in6.sin6_flowinfo` **before** `connect()`
and enable send, alongside the existing `SO_RCVTIMEO/SO_SNDTIMEO` calls (`connect.c:138-139`):
```c
int on = 1;
setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on));
((struct sockaddr_in6 *)dst)->sin6_flowinfo = htonl(scitag_flowlabel_encode(exp, act));
/* then the existing non-blocking connect(fd, dst, ...) */
```
For **WebDAV TPC libcurl** sockets, do the same inside the `CURLOPT_OPENSOCKETFUNCTION` callback
(we own the fd there before curl connects) — set `sin6_flowinfo` on the `curl_sockaddr` if it is
AF_INET6, or call the case-(a) MGR path after connect; this is also where firefly `flow_begin` runs.

**Operational/kernel caveats (MUST be documented for operators, and probed at runtime):**
- Stamping a *specific* (non-kernel-chosen) label can require the host sysctls
  `net.ipv6.flowlabel_state_ranges` / `net.ipv6.auto_flowlabels`, and `IPV6_FL_F_CREATE` for some
  label ranges needs `CAP_NET_ADMIN`. `flowlabel.c` MUST do a **one-time capability probe** at
  worker init (attempt a label lease on a throwaway socket); if it fails, log ONE clear WARN
  ("IPv6 flow-label marking unavailable: <reason>; firefly-only"), set a per-worker
  `flowlabel_usable=0`, and skip the per-flow calls. Never fail a transfer or spam the log.
- `IPV6_FLOWINFO`/`IPV6_FLOWLABEL_MGR` live in `<linux/in6.h>` + `<netinet/in.h>` — Linux-only.
  Guard the file with `#if defined(__linux__)` and compile to a no-op elsewhere (we are Linux in
  practice; keeps the tree portable).
- Label leases are per-socket and released when the fd closes — no explicit cleanup needed; the
  flow's firefly `flow_end` and the socket close cover teardown.
- `pmark_domain` still applies (don't label `local`-domain flows if configured `remote`).

**`xrootd_pmark_flowlabel` semantics:** `on` (default when `xrootd_pmark on`) = attempt the above
on every eligible IPv6 socket; `off` = never. It is independent of `xrootd_pmark_firefly`, so a
site may run flow-label-only, firefly-only, or (default) both — matching XRootD's
`use [no]flowlabel | [no]firefly` orthogonality (`XrdNetPMarkCfg.cc:1184-1207`).

---

## 7. Identity → (experiment, activity) mapping

`mapping.c getCodes()` replicates XRootD priority using **our** unified identity
(`src/core/types/identity.h`): `vo_list`/`primary_vo` for the VO rule, `dn`/`subject` for the user
rule, FQAN role for the role rule, request path for the path rule, and `scitag.flow` (CGI/header)
as the top-priority override. Output `(exp,act)` validated against ranges (1..1023 / 1..63);
invalid ⇒ no marking (fail-open: never break a transfer because of SciTags).

`defsfile.c` loads the scitags registry (names↔ids) so config uses **names** (`atlas`,
`write_production`) and we resolve to numeric ids — exactly XRootD's model. Missing defsfile with
declared mappings = config error at load (`nginx -t` fails), matching `pmark` `fail` semantics;
`nofail` downgrades to a warning + disables marking.

---

## 8. Metrics & dashboard
- New counters in `src/observability/metrics/` (low-cardinality only — INVARIANT #8: no per-flow labels):
  `pmark_flows_started`, `pmark_flows_ended`, `pmark_firefly_sent`, `pmark_firefly_dropped`
  (EAGAIN/err), `pmark_flowlabel_set`, `pmark_map_unresolved`.
- Optionally a small `/xrootd/api` dashboard panel: active flow count, last firefly error.
- **No experiment/VO/path in metric labels** (cardinality) — aggregate counts only.

---

## 9. Open decisions
- **D1 — HTTP plain transfers:** TPC-only (strict XRootD parity) vs also plain GET/PUT (superset).
  *Recommendation:* default parity, opt-in `xrootd_pmark_http_plain`.
- **D2 — IPv6 flow-label:** ~~implement the part XRootD left TODO?~~ **RESOLVED — REQUIRED.**
  Flow-label marking is a mandatory deliverable (full spec §6.4), default `on`, completing XRootD's
  `TODO???`. Remaining sub-decision is only the **encoding nibble/layout**, which MUST be pinned to
  the deployed SciTags Flow Label spec version in the single `scitag_flowlabel_encode()` function;
  confirm against the site's collector on a dual-stack test host. The kernel-privilege caveat
  (CAP_NET_ADMIN / sysctls for specific labels) is handled by the runtime fail-open probe (§6.4).
- **D3 — defsfile URL fetch:** subprocess curl/wget (XRootD style) vs native fetch vs local-only.
  *Recommendation:* local file in phase 1 (jansson); URL fetch is phase 2 (and a SSRF surface —
  reuse the `net_target.c` egress gating from phase-28 if added).
- **D4 — "ongoing" echo:** XRootD ships it disabled. *Recommendation:* implement it with an
  nginx timer (cheap on the event loop) since it's genuinely useful for long transfers, default off.

## 10. Out of scope
- A firefly **collector** (`flowd`) — we only emit; the site runs the standard collector.
- Non-TCP / QUIC marking (phase-19 HTTP/3 would need its own flow-label handling).
- Auto-registration with the scitags flow-id registry service.

---

## 11. Milestones & build/test
1. **M1 — scaffolding + config:** `src/observability/pmark/{pmark.h,scitag.c,config.c}`, directives + merge,
   register in repo-root `config`, `./configure && make`. Unit-test flow-id encode/decode and
   `scitag.flow`/`SciTag:` parsing (success / out-of-range / malformed).
2. **M2 — firefly emit:** `firefly.c` + `sockstats.c`; per-worker UDP socket; begin/end on root://
   open/disconnect. Test: capture datagrams on a local UDP listener, assert JSON matches the
   XRootD template byte-shape (state, context ids, flow-id ip/port, usage bytes).
3. **M3 — mapping + defsfile:** `mapping.c`, `defsfile.c` (jansson). Test: VO/path/user/role/default
   resolution + the scitag-CGI override precedence; `nginx -t` fails on missing defsfile with `fail`.
4. **M4 — IPv6 flow-label marking (REQUIRED, §6.4):** `flowlabel.c` — `scitag_flowlabel_encode()`,
   the inbound `IPV6_FLOWLABEL_MGR` + `IPV6_FLOWINFO_SEND` path and the outbound `sin6_flowinfo`
   path, the worker-init capability probe + fail-open, and the IPv6/mapped applicability gate.
   Wire it into the same begin sites as firefly (root:// open, accepted fd). **Tests:** (success)
   on a dual-stack host, a root:// GET over IPv6 carries the encoded label — verify by capturing
   on the wire (`tcpdump 'ip6'` / `ss -6 -i`) and decoding `(label & 0xFFFF)` back to `(exp,act)`;
   (skip) IPv4 and `::ffff:` mapped peers are silent no-ops with firefly still emitted;
   (security/robustness) when the kernel denies the specific label (no CAP_NET_ADMIN / sysctl off),
   the probe trips once, `flowlabel_usable=0`, the transfer still succeeds, `pmark_flowlabel_failed`
   increments. Encoding round-trip unit test pins the bit layout to the SciTags spec version.
5. **M5 — TPC + HTTP + echo:** libcurl open/close-socket callbacks (WebDAV TPC, set `sin6_flowinfo`
   there too), native-TPC connect-site hook (label + firefly), `SciTag:` header for WebDAV/S3, and
   the optional "ongoing" echo timer (D4). Test: PULL/PUSH appname convention; end-firefly carries
   non-zero TCP_INFO bytes (close-cb ordering); outbound IPv6 TPC socket carries the label.
6. **M6 — metrics/dashboard + docs:** counters (incl. `pmark_flowlabel_set`/`_failed`), README,
   user docs under `docs/04-protocols/`, and an **interop test** against a real `flowd`/scitags
   collector (or the XRootD firefly schema validator) plus a flow-label decode check end-to-end.

> **Sequencing note:** M4 (flow-label) and M2 (firefly) are *both required* and independent; they
> can be built in either order after M1. Neither is gated on the other — a flow gets the label
> (in-band) and the firefly (out-of-band) from the same begin site.

**Per CLAUDE.md, every change ships 3 tests: success + error + security-negative.** Security-neg
examples: a client-supplied `scitag.flow=70000` (out of range) is ignored, not echoed and not
encoded into a flow label; a `scitag.flow` with injected `"` / newline cannot break out of the
firefly JSON (escape in `scitag.c`); a client-supplied label/tag can never widen authorization
(SciTags is accounting only — it MUST NOT feed auth/ACL decisions); marking never blocks or fails
a transfer (fail-open) — including the flow-label kernel path, which degrades to firefly-only when
the kernel denies the label; UDP send errors and `setsockopt` failures are counted, not surfaced
to the client.

**Build governance:** new `.c` ⇒ add to repo-root `config` `ngx_module_srcs` + one `./configure`;
struct-layout changes to `types/context.h`/`config.h` ⇒ full recompile
(`find src -name '*.c' -exec touch {} +; make`) to avoid mixed-ABI crashes.

---

## 12. Effort estimate
- M1–M3 (firefly core + config + mapping): the bulk; ~`src/observability/pmark/` 9 files, ~1.7–2.2k LoC.
- M4 (IPv6 flow-label, REQUIRED): small-to-moderate — `flowlabel.c` is compact (encode + two
  setsockopt paths + probe), but budget time for **dual-stack testing and the kernel-privilege
  matrix** (CAP_NET_ADMIN, `net.ipv6.flowlabel_state_ranges`/`auto_flowlabels`), which is the only
  genuinely environment-sensitive part of this phase.
- M5 (TPC/HTTP wiring + echo): moderate; reuses existing curl-opt + connect sites.
- M6 (metrics, docs, interop): small-to-moderate.

Risk is low and **fail-open by design**: SciTags never sits on the data path's critical success
path. Both required mechanisms degrade safely — firefly to "no datagram" on a collector outage,
flow-label to "no label" when the kernel refuses the lease — and **neither ever fails a transfer**.
The flow-label path is the one piece that depends on host kernel config; the worker-init capability
probe (§6.4) makes that dependency explicit and self-disabling rather than a runtime hazard.
