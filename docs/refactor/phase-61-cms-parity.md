# Phase 61 — CMS parity: close the remaining cmsd gaps

**Status:** plan / spec
**Date:** 2026-06-27
**Scope:** `src/cms/`, `src/manager/`, `src/frm/` (wiring only), config, tests, docs.
**Hard requirement:** **byte-exact wire interop** with stock `cmsd` — no wire
changes; every new opcode/field matches `XProtocol/YProtocol.hh` +
`XrdCms/XrdCmsParser.cc` layouts. **Non-goal:** the C++ plugin ABI; UDP monitoring.

---

## 0. Where we are

Implemented + fleet-tested (phases 28/50/59): the 2-tier redirector role —
login/xauth(sss)/heartbeat/space, registry-based **selection + redirect**, Plane A
liveness (`ping`/`pong`/`disc`/`update`/`statfs`), and Plane B **node execution**
of forwarded namespace ops (confined `chmod/mkdir/mkpath/mv/rm/rmdir/trunc`) +
the manager **redirect** orchestration for mutations.

This phase closes the breadth between that and full `cmsd`. Gaps below are grounded
in the current dispatch (`server_recv.c` / `recv.c` / `node_ops.c`), the router
tables (`router.c`), the selector (`registry_select.c`), and the official
`XrdCms` module set.

### Gap inventory (severity)

| # | Gap | Where | Sev |
|---|---|---|---|
| G1 | `usage`/`stats` routed but **not dispatched** (manager) | `server_recv.c` | med |
| G2 | `prepadd`/`prepdel` not executed on node; **no CMS↔FRM staging** | `recv.c`,`node_ops.c` | high |
| G3 | manager selects from **static login-Paths only**; no dynamic `state→have` cache; incoming `have` undispatched | `server_recv.c`,`manager/` | high |
| G4 | **load vector hollow** (cpu/io/net/mem/pag zeroed); no meter/perfmon | `send.c` | med |
| G5 | selection breadth: single-source, no affinity/`Pack`, no `try*` sub-reasons, no `blredir` | `registry_select.c`,`recv.c` | med |
| G6 | no **file-driven blacklist**; no **admin** control surface | — | low/med |
| G7 | **no multi-tier** (supervisor/meta-manager/man-tree) | — | high (large) |
| G8 | **Plane B multi-replica fan-out** (rm-from-all-holders) unwired | `forward.c` | med |
| G9 | `status` state machine partial; no `vnid`/`BaseFS` fast-exists | — | low |

---

## 1. Workstreams

### W1 — `usage` / `stats` query replies (G1)  · ~0.5 wk
Manager answers the two routed-but-dropped queries:
- **`usage`** (`do_Usage`): reply `kYR_load` reporting aggregate cluster space.
  Reuse the `lodArgs` wire shape from `send.c` (`theLoad` string + `dskFree` int);
  source from `xrootd_srv_aggregate_space`. New `xrootd_cms_srv_send_load(ctx,
  streamid)` mirroring `send_data`/`send_status`.
- **`stats`** (`do_Stats`): reply `kYR_data` with the cluster stats blob. v1 emits
  the size-only form (`CmsStatsRequest::kYR_size` modifier) + a minimal stats
  document; full XML parity deferred (needs a meta-manager peer to diff).
- Wire `CMS_RR_USAGE`/`CMS_RR_STATS` cases into `cms_srv_process_frame`.
- Tests: extend `test_cms_wire_pup_conformance.py` (golden frames).

### W2 — prepare/staging coordination (G2)  · ~1.5 wk  **[highest value]**
Make tape/staging work across the cluster:
- **Node side:** dispatch `CMS_RR_PREPADD`/`CMS_RR_PREPDEL` in `recv.c`; add the
  two actions to `node_ops.c`'s planner (`padArgs`/`pdlArgs` already decode via
  `rrdata.c`). Route into the **existing FRM request API** (`frm_request_*`,
  `src/query/prepare.c` is the reference consumer): `prepadd`→enqueue stage with
  reqid/notify/prty/path; `prepdel`→`frm_request_delete(reqid)`. Reply byte-exact
  (silent success / `kYR_error`), same as the other forwarded ops.
- **Manager side:** when a client `kXR_prepare` arrives in manager mode, forward
  `prepadd`/`prepdel` to the holding node(s) via `xrootd_cms_forward_to_node`
  (rendezvous with W8 for multi-holder), or redirect — ADR-1.
- Tests: forwarded prepadd creates an FRM queue entry on the node; prepdel removes
  it; `query prepare` reflects status.

### W3 — dynamic location: `state`→`have` collection on the manager (G3)  · ~1.5 wk
Today the top manager selects only from static login-`Paths`. Add the on-demand
model stock `cmsd` uses (`XrdCmsCache` + `do_Have`):
- Manager **sends `kYR_state`** to candidate nodes for a path it can't resolve from
  static registration, with a bounded fan-out + a short collection window.
- Manager **dispatches incoming `kYR_have`** (currently undispatched in
  `server_recv.c`) into a per-path location cache (TTL'd, in the SHM registry or a
  sidecar table), so subsequent locates are O(1).
- Honour the `CMS_HAVE_ONLINE` modifier (resident vs needs-stage) to drive W2.
- Tests: node holds a file not in its login-Paths prefix → manager state-probes →
  node `kYR_have` → client redirected; negative → NotFound after the window.

### W4 — real load metering + perf-monitor hook (G4)  · ~1 wk
- Compute a real load vector (cpu/io/net/mem/pag) for the `kYR_load` `theLoad`
  string instead of zeros — a lightweight native meter (`/proc/loadavg`, `/proc`
  net/io counters) analogous to `XrdCmsMeter`.
- Optional pluggable hook seam mirroring `XrdCmsPerfMon` (native callback, **not**
  the C++ ABI) so a site can supply a custom load number.
- Feed the vector into `registry_select` scoring (weight load alongside space/util).
- Tests: heartbeat carries a non-zero load vector; selection shifts under load.

### W5 — selection breadth (G5)  · ~1.5 wk
- **Multi-source** locate replies (return N servers, not one) for client-side
  failover; emit the ordered `kYR_try` list accordingly.
- **Affinity / `Pack`** selection (XrdCmsSelect `Pack`) so repeated opens of one
  path stick to one server (cache locality).
- **`kYR_try*` sub-reasons** (`tryMISS`/`tryIOER`/`tryRSEG`/`trySVER`/…) and
  **`kYR_blredir`** bounce-list semantics in the redirect path (`recv.c` +
  `read/open_request.c`).
- Tests: N-server locate ordering; affinity stickiness; try-reason propagation.

### W6 — blacklist file + admin surface (G6)  · ~1 wk
- **File-driven blacklist** (`XrdCmsBlackList`): a re-read-on-change blacklist file
  (`xrootd_cms_blacklist_file`) that excludes hosts/CIDRs from selection, layered
  over the existing runtime 30 s disconnect-blacklist in `registry_select`.
- **Admin surface**: rather than the `XrdCmsAdmin` local Unix-socket command set,
  expose drain/undrain/blacklist/list via the existing **dashboard API**
  (`src/dashboard/`) — native and authenticated (ADR-2).
- Tests: blacklisted host never selected; file reload picks up edits; dashboard
  drain removes a node from selection.

### W7 — multi-tier clustering (G7)  · ~3–4 wk  **[large; candidate for its own phase]**
Supervisor / meta-manager / sub-manager cascades (`XrdCmsSupervisor`,
`XrdCmsManTree`, `manVOps` routing). A node runs as **both** a manager (accepting
nodes below) and a heartbeat client (registering up to a meta-manager); locates
recurse up the tree with hop-count limits. We already have both halves (client +
server) in `src/cms/` and the sub-manager `state→have` forwarding on the node side
— W7 is the tree formation, recursion, and `metaman`/`subman` login modes + the
meta-manager-restricted routing table (`manVOps`). **Recommend splitting to
phase-62** given size; this phase delivers G1–G6, G8–G9.

### W8 — Plane B multi-replica fan-out (G8)  · ~1.5 wk
The manager forwards a mutation to **every** holder (so `rm` clears all replicas)
instead of redirecting to one. The blocker is cross-worker: node CMS connections
live on whichever worker accepted them. Approach (ADR-3): a per-worker forward +
an SHM "pending forwarded-op" aggregation table keyed by streamid, with a
designated-worker or broadcast-to-workers fan-out; aggregate `Repliable` replies,
honour `Delayable`→`kYR_wait`. Reuses `xrootd_cms_forward_to_node` (the wire
primitive, already unit-tested) + the node executor.
Tests: rm of a 2-replica file removes both; partial-failure → first/worst error.

### W9 — status state machine + vnid/BaseFS (G9)  · ~0.5 wk
- Complete the `kYR_status` transitions (suspend/resume/**reset**/staging-state)
  on both halves.
- `vnid` (virtual network id) passthrough in login for multi-homed nodes.
- A `BaseFS`-style fast existence check (stat-only) before a full state probe.

---

## 2. Effort summary

| WS | Gap | Effort |
|---|---|---|
| W1 | usage/stats replies | 0.5 wk |
| W2 | prepare/staging (CMS↔FRM) | 1.5 wk |
| W3 | dynamic state→have cache | 1.5 wk |
| W4 | load metering + perfmon hook | 1.0 wk |
| W5 | selection breadth | 1.5 wk |
| W6 | blacklist file + admin | 1.0 wk |
| W8 | multi-replica fan-out | 1.5 wk |
| W9 | status/vnid/BaseFS | 0.5 wk |
| **subtotal (this phase, G1–G6,G8–G9)** | | **≈ 9 wk** |
| W7 | multi-tier (→ **phase-62**) | 3–4 wk |

Quick wins first: **W1** then **W9** (small, high-confidence). Highest value:
**W2** (staging) and **W3** (dynamic location). Largest/riskiest: **W7** (split)
and **W8** (cross-worker).

## 3. Testing strategy

- **Wire conformance:** extend `tests/test_cms_wire_pup_conformance.py` with golden
  frames for every new opcode/reply (usage/stats/prepadd/prepdel/have/multi-try).
- **Standalone unit:** the `rrdata`/`router` suites already cover decode/routing;
  add load-vector + selection-scoring unit checks.
- **Fleet:** extend `test_manager_mode.py` (the live manager+node cluster) and
  `test_cms_state_have_select.py` for dynamic location, staging, multi-replica,
  blacklist, affinity. Validate against a **real `cmsd`** where the harness has one.
- **Regression gate:** the existing 42 CMS tests stay green per workstream.

## 4. Risks

- **No meta-manager peer in the fleet** → `stats` full-form and multi-tier (W7) are
  hard to byte-validate; keep W1 `stats` to the size-only form until a peer exists.
- **W8 cross-worker** correctness (SHM aggregation, teardown races) — the same
  class of bug as the shmtx postmortem; design carefully, reuse spin+yield slots.
- **W4 load semantics** must not destabilise selection — ship behind a weight knob,
  default to current space/util behaviour.

## Z. ADR log

- **ADR-1:** client `kXR_prepare` in manager mode → **forward** prepadd/prepdel to
  holders (not redirect), because staging must hit the node that has/will-have the
  file; pairs with W8 for multi-holder.
- **ADR-2:** expose admin/drain/blacklist via the **dashboard API** (native,
  authenticated), not the C++ `XrdCmsAdmin` Unix-socket command set.
- **ADR-3:** multi-replica fan-out via per-worker forward + SHM pending-aggregation
  (cross-worker), reusing `xrootd_cms_forward_to_node`.
- **ADR-4:** multi-tier (W7) splits to **phase-62** — it is a subsystem (tree
  formation + recursion + meta/sub login modes), not a workstream.
- **ADR-5 (unchanged policy):** no C++ plugin ABI; no UDP f/g-stream monitoring
  (Prometheus/SRR/dashboard instead).

---

# Appendix A — code-level skeletons (per workstream)

Grounded on current signatures: `send.c` builders (`ngx_xrootd_cms_send_load/
have/avail`, `put_short/put_int/put_string`); `manager/registry.h`
(`xrootd_srv_aggregate_space`, `xrootd_srv_locate_all`, `xrootd_srv_count_matching`,
`xrootd_srv_blacklist`, `xrootd_srv_snapshot`, `xrootd_srv_register`); `frm.h`
(`frm_request_add(q, frm_req_view_t*, …)`, `frm_request_delete(q, reqid, log)`);
`node_ops.h` action enum; `pending.h` (`xrootd_pending_lookup/remove/unlock`);
`YProtocol.hh` `kYR_try*` reasons. Server-side replies reuse
`xrootd_cms_srv_send_{frame,data,status}` (`server_send.c`).

## A.1 — W1 usage / stats replies

```c
/* server_send.c — usage(do_Usage) → kYR_load; mirror client send_load layout:
 *   theLoad = [u16 len=6][cpu,net,xeq,mem,pag,dsk] ; then put_int(free_mb)      */
ngx_int_t
xrootd_cms_srv_send_load(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
                         const uint8_t load6[6], uint32_t free_mb) {
    u_char p[16], *c = p;
    ngx_xrootd_cms_put16(c, 6); c += 2; ngx_memcpy(c, load6, 6); c += 6;
    c = ngx_xrootd_cms_put_int(c, free_mb);
    return xrootd_cms_srv_send_frame(ctx, streamid, CMS_RR_LOAD, 0, p, c - p);
}

/* server_recv.c — cms_srv_process_frame: */
case CMS_RR_USAGE: {
    uint32_t fmb = 0, util = 0;  uint8_t load6[6];
    xrootd_srv_aggregate_space(&fmb, &util);
    xrootd_cms_load_vector(load6);                 /* W4; zeros until then */
    xrootd_cms_srv_send_load(ctx, streamid, load6, fmb);
    break;
}
case CMS_RR_STATS: {                               /* size-only form (kYR_size) */
    u_char b[4]; uint32_t sz = xrootd_cms_stats_blob_len();
    ngx_xrootd_cms_put32(b, sz);
    xrootd_cms_srv_send_data(ctx, streamid, b, 4); /* full XML blob = follow-on */
    break;
}
```

## A.2 — W2 prepare/staging (node executes forwarded prepadd/prepdel → FRM)

```c
/* node_ops.h — extend the action enum + planner output */
typedef enum { ... XRDCMS_NACT_TRUNC, XRDCMS_NACT_PREPADD, XRDCMS_NACT_PREPDEL }
    xrootd_cms_node_action_t;
/* plan also surfaces reqid/notify/prty for prepadd (already decoded by rrdata) */

/* node_ops.c — xrootd_cms_node_plan(): add the two cases (padArgs/pdlArgs) */
case K_PREPADD:                                    /* needs path + reqid       */
    if (!path || !field_str(d->reqid,d->reqid_len)) return -1;
    plan->action = XRDCMS_NACT_PREPADD; plan->reqid = (const char*)d->reqid;
    plan->notify = (const char*)d->notify; plan->prty = (const char*)d->prty;
    return 0;
case K_PREPDEL:
    if (!field_str(d->reqid,d->reqid_len)) return -1;
    plan->action = XRDCMS_NACT_PREPDEL; plan->reqid = (const char*)d->reqid;
    return 0;

/* recv.c — dispatch + FRM wiring (reuse frm_request_add/delete, like prepare.c) */
case CMS_RR_PREPADD:
case CMS_RR_PREPDEL: {
    xrootd_cms_rrdata_t d; xrootd_cms_node_plan_t pl;
    if (rrparse(code,payload,plen,&d) || xrootd_cms_node_plan(code,&d,&pl))
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "bad prep");
    frm_queue_t *q = ctx->conf->frm.queue;
    if (pl.action == XRDCMS_NACT_PREPADD) {
        frm_req_view_t v = { .lfn = pl.path, .reqid = pl.reqid,
                             .notify = pl.notify /*, prty*/ };
        char out[XROOTD_FRM_REQID_LEN];
        (void) frm_request_add(q, &v, out, sizeof(out), ctx->cycle->log);
    } else {
        (void) frm_request_delete(q, pl.reqid, ctx->cycle->log);
    }
    return NGX_OK;                                  /* silent success (cmsd) */
}
```

## A.3 — W3 dynamic location (manager: send state, dispatch have, cache)

```c
/* a TTL'd path→location cache (sidecar SHM table, spin+yield slots per the
 * shmtx postmortem — NEVER the POSIX-sem mutex) */
typedef struct { char path[1024]; char host[256]; uint16_t port;
                 ngx_msec_t expires; unsigned online:1; } xrootd_loc_entry_t;
int  xrootd_loc_lookup(const char *path, char *host, size_t, uint16_t *port);
void xrootd_loc_insert(const char *path, const char *host, uint16_t port,
                       int online, ngx_msec_t ttl);

/* server_send.c — manager probes a node it can't resolve statically */
ngx_int_t xrootd_cms_srv_send_state(xrootd_cms_srv_ctx_t *ctx, uint32_t sid,
                                    const char *path, size_t plen) {
    /* raw NUL-terminated path, modifier=CMS_MOD_RAW (mirrors node send_have) */
    return xrootd_cms_srv_send_frame(ctx, sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     (const u_char*)path, plen + 1);
}

/* server_recv.c — dispatch incoming kYR_have into the cache (G3) */
case CMS_RR_HAVE: {
    if (!ctx->logged_in) break;
    int online = (modifier & CMS_HAVE_ONLINE) != 0;
    char path[1024]; size_t n = copy_raw_path(payload, payload_len, path);
    if (n) xrootd_loc_insert(path, ctx->host, ctx->port, online, /*ttl*/ 30000);
    break;
}
/* locate path: registry static-prefix select first; on miss, fan a bounded
 * kYR_state to candidates, collect kYR_have within a short window, then redirect
 * (or NotFound). The client stays suspended via the existing pending table. */
```

## A.4 — W4 real load vector

```c
/* a tiny native meter (no XrdCmsMeter C++); fill the 6 theLoad bytes */
void xrootd_cms_load_vector(uint8_t out[6]) {     /* cpu,net,xeq,mem,pag,dsk */
    out[0] = pct_from_loadavg();                  /* /proc/loadavg / ncpu     */
    out[1] = pct_from_proc_net_dev_delta();       /* nic utilisation          */
    out[2] = 0;                                    /* xeq (queue) — optional   */
    out[3] = pct_from_proc_meminfo();             /* mem used                 */
    out[4] = pct_from_paging_delta();             /* pgmajfault rate          */
    out[5] = export_fs_util_pct();                /* statvfs (already have)   */
}
/* registry_select scoring gains a load weight behind a knob (default off →
 * current space/util behaviour byte-identical) */
```

## A.5 — W5 selection breadth

```c
/* multi-source: xrootd_srv_locate_all already returns an ordered candidate set */
int n = xrootd_srv_locate_all(path, for_write, hosts, ports, MAX_TRY);
/* emit a kYR_try list (host\0port…) instead of one kYR_select host */

/* affinity/Pack: stick repeated opens of one path to one server */
if (conf->cms_affinity && count > 1)
    chosen = candidates[ hash32(path) % count ];   /* cache locality */

/* kYR_try sub-reasons (YProtocol): set in the redirect/try modifier so a client
 * tracks WHY it was bounced (drives tried/triedrc convergence) */
#define KYR_TRY_MISS 0x00000000  /* enoent  */   #define KYR_TRY_IOER 0x00010000
#define KYR_TRY_FSER 0x00020000                  #define KYR_TRY_SVER 0x00030000
#define KYR_TRY_RSEL 0x00040000 /* resel-LCL*/   #define KYR_TRY_RSEG 0x00080000
/* + kYR_blredir bounce-list redirect for "ask these others" */
```

## A.6 — W6 blacklist file + dashboard admin

```c
/* file-driven blacklist (XrdCmsBlackList): re-read on mtime change, apply over
 * the runtime 30s disconnect-blacklist already in registry_select */
void xrootd_cms_blacklist_reload(const char *file) {     /* host or CIDR/line */
    for each line:  xrootd_srv_blacklist(host, port, /*permanent*/ 0);
}
/* poll the file mtime from the existing low-rate manager timer (no new thread) */

/* admin via the dashboard API (src/dashboard/api_admin.c), authenticated:
 *   GET  /xrootd/api/v1/cms/nodes          -> xrootd_srv_snapshot()
 *   POST /xrootd/api/v1/cms/drain {host}   -> xrootd_srv_blacklist()
 *   POST /xrootd/api/v1/cms/undrain {host} -> xrootd_srv_undrain()           */
```

## A.7 — W8 multi-replica fan-out (cross-worker)

```c
/* manager forwards a mutation to EVERY holder + aggregates replies.
 * SHM pending-aggregation keyed by a manager-issued streamid (spin+yield slots) */
typedef struct { uint32_t sid; ngx_pid_t origin_pid; int origin_fd;
                 uint16_t expected, got, worst_err; ngx_msec_t deadline;
                 u_char client_streamid[2]; } xrootd_cms_fwd_agg_t;

int holders = xrootd_srv_locate_all(path, /*write*/1, hosts, ports, MAX);
for (i = 0; i < holders; i++)
    /* per-worker: forward on the node conn this worker owns; otherwise post to
     * the owning worker. forward primitive already exists + is unit-tested */
    xrootd_cms_forward_to_node(node_conn[i], code, agg->sid, ident,
                               path, path2, mode, opaque);
/* each node reply (silent ok / kYR_error) → agg->got++/worst_err; when
 * got==expected (or Delayable deadline) → reply to origin client (ok / error /
 * kYR_wait). Teardown-race-safe like the locate pending table. */
```

## A.8 — W9 status / vnid / BaseFS

```c
/* complete kYR_status transitions on both halves */
if (mod & CMS_ST_RESET)   xrootd_srv_registry_reset_node(host, port);
if (mod & CMS_ST_SUSPEND) ...   if (mod & CMS_ST_RESUME) ...   /* + staging bits */
/* vnid: carry the virtual-network id string in login (multi-homed nodes) */
/* BaseFS fast-exists: stat-only probe before a full kYR_state round-trip */
```

## A.9 — tests (per workstream, extend existing suites)

```python
# test_cms_wire_pup_conformance.py — golden frames
def test_usage_returns_load(cms_server): ...        # W1
def test_stats_size_form(cms_server): ...           # W1
def test_forwarded_prepadd_enqueues_frm(node_stack):# W2 (node + FRM)
def test_state_probe_then_have_caches(cms_server):  # W3
def test_load_vector_nonzero(node_stack):           # W4
# test_manager_mode.py — live cluster
def test_locate_multi_source_try_list(cluster): ... # W5
def test_affinity_sticky(cluster): ...              # W5
def test_blacklist_file_excludes(cluster): ...      # W6
def test_rm_clears_all_replicas(cluster): ...       # W8
```

---

# Appendix B — wire layouts, sequences, change manifest, config, tests

All frames share the 8-byte `CmsRRHdr` (confirmed in `frame_io.c`):

```
off 0..3  streamid   u32 BE        off 4  rrCode  u8
off 5     modifier   u8            off 6..7 dlen  u16 BE     then dlen payload bytes
```
Pup string = `[u16 len incl NUL BE][bytes][NUL]`; Pup int = `[0xa0][u32 BE]`;
Pup short = `[0x80][u16 BE]`.

## B.1 New / completed reply frames (byte-exact)

**W1 `usage`→`kYR_load`** (code 16; mirrors `send_load`):
```
hdr{sid=echo, code=16, mod=0, dlen=13}
payload: 00 06 | cpu net xeq mem pag dsk | a0 <free_mb u32 BE>      (2+6+5 = 13)
```

**W1 `stats`→`kYR_data` size-form** (resp code 0, `kYR_size` modifier on the req):
```
hdr{sid=echo, code=0(kYR_data), mod=0, dlen=4}   payload: <statsz u32 BE>
```

**W3 manager `state` probe** (code 20, raw):
```
hdr{sid, code=20, mod=0x20(CMS_MOD_RAW), dlen=plen+1}   payload: "<path>\0"
```
**W3 node `have`** (code 15, raw|online) — already emitted by `send_have`:
```
hdr{sid=echo, code=15, mod=0x20|0x01(RAW|ONLINE)}       payload: "<path>\0"
```

**W2 forwarded `prepadd`** (code 6; `padArgs` order):
```
hdr{sid, code=6, mod=0, dlen=Σ}
payload: pup(ident) pup(reqid) pup(notify) pup(prty) pup(mode) pup(path)
```
**W2 forwarded `prepdel`** (code 7; `pdlArgs`): `pup(ident) pup(reqid)`.

**Error reply** (resp code 1) — already in `send_error`:
```
hdr{sid=echo, code=1(kYR_error), dlen=4+n}   payload: <ecode u32 BE>"<text>\0"
```

**W5 multi-source `try`** (code 24; ordered alternatives), modifier carries the
`kYR_try*` reason in its high bits per `YProtocol`:
```
hdr{sid=echo, code=24, mod=<reason>, dlen=Σ}
payload: "<host1>\0"<port1 u16 BE>"<host2>\0"<port2 u16 BE> …
```

## B.2 Sequence diagrams

**W2 — client prepare (stage) across the cluster**
```
client            manager(xrootd)         node(xrootd+frm)
  | kXR_prepare(stage,/lfn) |                   |
  |------------------------>|                   |
  |        select holder(s) (locate_all)        |
  |          | kYR_prepadd(reqid,/lfn) ───────> |  recv.c → frm_request_add()
  |          |                  (silent ok)     |  → FRM queue (STAGING)
  |<-- kXR_ok "reqid" -------|                   |
  | kXR_query(prepare,reqid)|  status from FRM   |
  |<-- staged/online --------|                   |
```

**W3 — dynamic location on a static-registration miss**
```
client            manager                       nodeA   nodeB
  | kXR_open /x |  loc_lookup(/x) miss → fan state probe (bounded window)
  |----------->|  kYR_state(/x) ─────────────────> |       |
  |            |  kYR_state(/x) ─────────────────────────> |
  |            |<── kYR_have(/x, ONLINE) from nodeB ──────  |
  |            |  loc_insert(/x→nodeB, ttl)                 |
  |<- kXR_redirect nodeB --|                                |
  (no have within window → kXR_error NotFound)
```

**W8 — multi-replica rm (fan-out + aggregate)**
```
client          manager (agg sid=S, expected=2)        nodeA  nodeB
  | kXR_rm /x |  locate_all(/x)=[A,B]                     |      |
  |---------->|  forward_to_node(rm, S, /x) ───────────-> |      |
  |           |  forward_to_node(rm, S, /x) ────────────────────>|
  |           |<─ (silent ok | kYR_error) from A,B  → got==expected
  |<- kXR_ok (or first/worst error) --|                  |      |
```

## B.3 File / function change manifest

| WS | Files touched | Add / modify |
|---|---|---|
| W1 | `cms/server_send.c`,`server.h`,`server_recv.c` | + `xrootd_cms_srv_send_load`; `USAGE`/`STATS` cases |
| W2 | `cms/node_ops.{c,h}`,`cms/recv.c` | + `NACT_PREPADD/PREPDEL` + planner; dispatch → `frm_request_add/delete` |
| W3 | new `manager/loc_cache.{c,h}`; `cms/server_send.c`,`server_recv.c`,`manager/registry_select.c` | loc cache (SHM, spin+yield); `send_state`; `HAVE` dispatch; locate-miss probe |
| W4 | new `cms/meter.{c,h}`; `cms/send.c`,`manager/registry_select.c` | `xrootd_cms_load_vector`; non-zero `theLoad`; load-weighted score |
| W5 | `manager/registry_select.c`,`cms/recv.c`,`read/open_request.c` | multi-source via `locate_all`; affinity hash; `try*`/`blredir` |
| W6 | new `cms/blacklist_file.{c,h}`; `dashboard/api_admin.c`,`config/*` | file reload→`srv_blacklist`; `/cms/*` admin endpoints |
| W8 | new `cms/forward_agg.{c,h}`; `cms/forward.c`,`handshake/dispatch_write.c` | SHM pending-agg; fan-out at the mutation gate |
| W9 | `cms/recv.c`,`server_recv.c`,`cms/send.c` | status reset/staging; vnid in login; BaseFS fast-exists |

New `.c` files register in top-level `./config` (`NGX_ADDON_SRCS`), then
`./configure`. Pure-C bits (loc cache key match, meter parse, blacklist parse,
agg state) get standalone `*_unittest.c` like `rrdata`/`router`.

## B.4 New config directives (`ngx_command_t`, mirror `xrootd_cms_server_*`)

```c
{ ngx_string("xrootd_cms_blacklist_file"), NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_str_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, cms_blacklist_file), NULL },     /* W6 */
{ ngx_string("xrootd_cms_affinity"), NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_flag_slot, ..., offsetof(..., cms_affinity), NULL },        /* W5 */
{ ngx_string("xrootd_cms_load_weight"), NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_num_slot, ..., offsetof(..., cms_load_weight), NULL },      /* W4 */
{ ngx_string("xrootd_cms_locate_window"), NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_msec_slot, ..., offsetof(..., cms_locate_window_ms), NULL },/* W3 */
{ ngx_string("xrootd_cms_state_cache_ttl"), ... cms_loc_ttl_ms ... },      /* W3 */
```
Defaults keep current behaviour: affinity off, load_weight 0 (space/util only),
locate_window 0 (static-registration-only, no probe), cache_ttl 30s.

## B.5 Test matrix (3-per-change: success · error · security-neg)

| WS | success | error | security-neg |
|---|---|---|---|
| W1 | usage→load bytes; stats→size | malformed query frame dropped | pre-auth usage ignored |
| W2 | prepadd enqueues FRM entry; prepdel removes | bad reqid → `kYR_error` | path `../escape` in prep refused (confined) |
| W3 | state→have caches; redirect | no-have window → NotFound | hostile `have` for foreign path not cached/served |
| W4 | non-zero load vector; score shifts | meter read failure → zeros (no crash) | n/a |
| W5 | N-server try ordering; affinity sticky | all-tried → NotFound (no loop) | injected host in try-list rejected (host allowlist) |
| W6 | blacklisted host never selected; reload | malformed blacklist line skipped | admin endpoint requires auth (403 anon) |
| W8 | rm clears both replicas | one node errors → first/worst to client | forwarded op still confined on each node |
| W9 | reset clears node state | unknown status mod → no-op | n/a |

Per-workstream regression gate: the existing **42 CMS tests stay green**; add the
new golden frames to `test_cms_wire_pup_conformance.py` and the live cases to
`test_manager_mode.py` / `test_cms_state_have_select.py`.

---

# Appendix C — full designs for the hard pieces (W3, W8) + a drop-in W1

Appendices A/B sketch all nine workstreams; the two genuinely
concurrency-sensitive ones get a complete design here, modelled on the existing
SHM registry (`{ngx_shmtx_sh_t lock; capacity; slots[]}`, spin+yield mutex per
INVARIANT #10 — **never** the POSIX-sem mode) and the pid-keyed cross-worker
pending table (`xrootd_pending_insert/lookup/remove`). W1 is given fully
drop-in as the worked example.

## C.1 — W3 location cache: SHM design (grounded on `registry.h` + `shm_slots.h`)

### Data layout (one dedicated shm zone, like `xrootd_srv_shm_zone`)
```c
/* manager/loc_cache.h */
typedef struct {
    uint32_t   path_hash;          /* fnv1a(path); 0 = free slot               */
    char       path[1024];         /* full key (collision-safe compare)         */
    char       host[256];
    uint16_t   port;
    unsigned   online:1;           /* CMS_HAVE_ONLINE → resident vs needs-stage */
    ngx_msec_t expires;            /* ngx_current_msec + ttl; 0 = none          */
} xrootd_loc_entry_t;

typedef struct {                   /* lock MUST be first (ngx_shmtx_create)     */
    ngx_shmtx_sh_t      lock;
    ngx_uint_t          capacity;  /* power-of-two; open-addressing             */
    xrootd_loc_entry_t  slots[];   /* C99 flexible array                        */
} xrootd_loc_table_t;

extern ngx_shm_zone_t *xrootd_loc_shm_zone;
```

### Zone init (mirror `xrootd_srv_shm_init_zone`, spin+yield mutex)
```c
ngx_int_t xrootd_loc_shm_init_zone(ngx_shm_zone_t *zone, void *data) {
    xrootd_loc_table_t *t = xrootd_shm_table_alloc(zone, data, /*hdr*/sizeof(*t),
                                                   sizeof(xrootd_loc_entry_t));
    if (!t) return NGX_ERROR;
    if (data == NULL) {                      /* fresh boot */
        t->capacity = loc_slots;             /* xrootd_cms_state_cache_slots */
        ngx_memzero(t->slots, t->capacity * sizeof(t->slots[0]));
    }
    /* spin+yield, NEVER POSIX-sem — clears mtx->semaphore (INVARIANT #10) */
    return xrootd_shm_table_mutex_create(&t->lock, zone);
}
```

### Insert / lookup (open-addressing, TTL-lazy-evict, spinlock-held µs)
```c
void xrootd_loc_insert(const char *path, const char *host, uint16_t port,
                       int online, ngx_msec_t ttl) {
    xrootd_loc_table_t *t = xrootd_loc_shm_zone->data;
    uint32_t h = fnv1a(path), i = h & (t->capacity - 1), n = 0;
    ngx_shmtx_lock(&mtx(t));
    for (; n < t->capacity; n++, i = (i + 1) & (t->capacity - 1)) {
        xrootd_loc_entry_t *e = &t->slots[i];
        if (e->path_hash == 0 || e->path_hash == h
            || e->expires <= ngx_current_msec) {        /* free / match / stale */
            e->path_hash = h; ngx_cpystrn((u_char*)e->path,(u_char*)path,sizeof e->path);
            ngx_cpystrn((u_char*)e->host,(u_char*)host,sizeof e->host);
            e->port = port; e->online = !!online;
            e->expires = ttl ? ngx_current_msec + ttl : 0; break;
        }
    }
    ngx_shmtx_unlock(&mtx(t));                            /* full table → drop (best-effort cache) */
}
int xrootd_loc_lookup(const char *path, char *host, size_t hs, uint16_t *port,
                      int *online) {
    /* same probe; skip expired; on hit copy host/port/online; return 1/0.
     * spinlock held only for the bounded scan — µs, matches registry policy. */
}
```

### Locate-miss orchestration (bounded fan-out + collection window)
On a static-registration miss for `/x`:
1. `xrootd_loc_lookup(/x)` — hit ⇒ redirect immediately.
2. else snapshot candidates (`xrootd_srv_snapshot`), `send_state(/x)` to up to
   `cms_state_fanout` of them; arm a `cms_locate_window_ms` timer; suspend the
   client in `XRD_ST_WAITING_CMS` (the **existing** pending table keyed by sid+pid).
3. each incoming `kYR_have` (server_recv `CMS_RR_HAVE` case) →
   `xrootd_loc_insert` **and**, if a client waits on this path, wake it
   (`cms_wake_pending_session`-style redirect). First `have` wins.
4. window expires with no `have` ⇒ `kXR_error NotFound` (or fall through to
   static select). Bounded, no busy-loop (timer floor, like the FRM/CMS timers).

**Security:** a node may only assert `have` for a path under one of its
login-`Paths` prefixes (validate against the registry entry before caching),
mirroring the `kYR_state` confinement — a hostile node can't poison locations for
paths it doesn't export.

## C.2 — W8 cross-worker forward aggregation (the multi-replica `rm` problem)

**Problem.** Node CMS connections live on whichever worker accepted them; a
client mutation arrives on an arbitrary worker. Worker A can't write worker B's
sockets. **Solution:** an SHM aggregation table (cross-worker, like pending) +
per-worker forwarding of the nodes each worker owns, finalized by the worker that
owns the originating client.

### SHM agg table (keyed by a manager-issued streamid)
```c
typedef struct {
    uint32_t          sid;            /* manager-issued correlation id; 0 = free */
    ngx_pid_t         origin_pid;     /* worker holding the client (finalizer)   */
    int               origin_fd;      /* client conn fd (+ generation guard)     */
    ngx_atomic_uint_t origin_conn;    /* conn->number guard (recycle-safe)       */
    u_char            client_streamid[2];
    uint16_t          expected;       /* # holders the fan-out targets           */
    uint16_t          got;            /* replies seen (atomic inc)               */
    uint16_t          worst_err;      /* 0 = ok; else first/worst kXR code        */
    ngx_msec_t        deadline;       /* Delayable → kYR_wait then finalize       */
} xrootd_cms_fwd_agg_t;               /* same {lock; cap; slots[]} shell + spinlock */
```

### Flow
1. Mutation gate (`handshake/dispatch_write.c`, manager mode): `locate_all(/x)`
   → holders `[A,B,…]`; `expected = N`. Allocate an agg slot (sid = next manager
   streamid); record origin pid/fd/conn/streamid. Suspend the client.
2. **Each worker** iterates the holders **it owns** a live CMS connection to and
   calls `xrootd_cms_forward_to_node(node_conn, op, sid, ident, /x, …)`. Holders
   on other workers are reached by posting a tiny "forward request" to those
   workers (reuse the existing inter-worker channel the pending/locate path uses),
   or — simpler v1 — only the worker(s) actually holding the node connections
   forward, which together cover all holders since every node connection lives on
   exactly one worker.
3. Each node reply (silent ok / `kYR_error`, server_recv) → find agg by sid under
   the spinlock, `got++`, fold `worst_err`. When `got == expected` (or `deadline`),
   the **origin worker** finalizes: resolve `origin_fd`+`origin_conn` to the live
   client (recycle-guarded, exactly like `cms_wake_pending_session`) and send
   `kXR_ok` / first-worst `kXR_error` / `kXR_wait`.
4. Teardown safety: client gone (conn number mismatch) ⇒ drop on finalize; agg
   slot reclaimed by sid reuse or deadline sweep.

**Why this is the right shape:** it reuses three proven patterns — the SHM
spin+yield table (registry), the pid+fd+generation client resolution (pending /
`cms_wake_pending_session`), and the unit-tested `forward_to_node` wire primitive
— so the only new risk surface is the agg counting, which is a bounded
spinlock-guarded critical section (µs), never a POSIX-sem (INVARIANT #10).
Single-replica stays on the **redirect** path (already shipped); fan-out engages
only when `locate_all` returns >1 holder.

## C.3 — W1 fully drop-in (the worked example)

```c
/* cms/server_send.c */
ngx_int_t
xrootd_cms_srv_send_load(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
    const uint8_t load6[6], uint32_t free_mb)
{
    u_char  p[16];
    u_char *c = p;
    ngx_xrootd_cms_put16(c, 6);  c += 2;        /* theLoad: bare [len][6 bytes] */
    ngx_memcpy(c, load6, 6);     c += 6;
    c = ngx_xrootd_cms_put_int(c, free_mb);     /* dskFree (tagged int)         */
    return xrootd_cms_srv_send_frame(ctx, streamid, CMS_RR_LOAD, 0,
                                     p, (size_t) (c - p));   /* dlen = 13 */
}

/* cms/server.h */
ngx_int_t xrootd_cms_srv_send_load(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
    const uint8_t load6[6], uint32_t free_mb);

/* cms/server_recv.c — cms_srv_process_frame(), before default: */
case CMS_RR_USAGE: {
    uint32_t free_mb = 0, util = 0;
    uint8_t  load6[6] = {0,0,0,0,0,0};          /* W4 fills these; 0 = parity */
    if (!ctx->logged_in) { break; }
    xrootd_srv_aggregate_space(&free_mb, &util);
    load6[5] = (uint8_t) (util > 100 ? 100 : util);   /* dsk util now; rest W4 */
    (void) xrootd_cms_srv_send_load(ctx, streamid, load6, free_mb);
    break;
}
case CMS_RR_STATS: {
    u_char   b[4];
    uint32_t statsz = 0;                         /* size-only form for v1 */
    if (!ctx->logged_in) { break; }
    ngx_xrootd_cms_put32(b, statsz);
    (void) xrootd_cms_srv_send_data(ctx, streamid, b, sizeof(b));
    break;
}
```
```python
# tests/test_cms_wire_pup_conformance.py  (golden, byte-exact)
def test_usage_returns_load(cms_server):
    sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
    sock.sendall(_build_frame(0, 26, 0, b""))            # kYR_usage
    sid, code, mod, body = _recv_code(sock, 16)          # kYR_load
    assert len(body) == 13
    assert body[0:2] == b"\x00\x06" and body[8] == 0xa0  # theLoad len + int tag
def test_stats_size_form(cms_server):
    ... sendall(_build_frame(0, 11, 0, b"")) ; expect code 0 (kYR_data), dlen 4
```

These three pieces — the SHM location cache, the cross-worker aggregator, and the
drop-in W1 — are the parts a reviewer would otherwise have to design from scratch;
everything else in W2/W4/W5/W6/W9 follows the existing handler/registry idioms in
Appendices A/B.

---

# Appendix D — corrected drop-in W2 (staging), landing sequence, observability

## D.0 Correction (grounded on the real FRM API)

`frm_req_view_t` is `{ const char *lfn (required); requester_dn; user; notify;
selector; cs_value; frm_cstype_t cs_type; uint32_t options (FRM_OPT_*);
int8_t priority(-1..2); uint8_t queue; int64_t tod_expire }` and
`frm_request_add(q, &view, reqid_out, sz, log)` **generates** the reqid (written
to `reqid_out`). The Appendix-A sketch's `view.reqid = …` was wrong — the view has
no reqid field.

**The real subtlety (ADR-6):** a CMS `prepadd` **carries** a reqid (so the
client's later `query prepare`/`prepdel` can name it), but `frm_request_add`
*mints* its own. Two ways to reconcile:
- **D-a (chosen):** keep a small per-node SHM map `cms_reqid → frm_reqid` (one
  more spin+yield slot table, §C idiom). `prepadd` adds via FRM, records the
  mapping; `prepdel`/status look up the FRM reqid by the CMS reqid. Zero FRM-core
  change; isolates the impedance mismatch in the CMS layer.
- **D-b (rejected):** add a `const char *reqid` to `frm_req_view_t` and an
  "honor caller reqid" path in `frm_request_add`. Smaller code but touches the FRM
  core + its dedup/uniqueness invariants — out of scope for a CMS-parity phase.

## D.1 W2 drop-in (accurate)

```c
/* cms/node_ops.h — plan carries the prep fields (decoded by rrdata padArgs/pdlArgs) */
typedef enum { /* … */ XRDCMS_NACT_PREPADD, XRDCMS_NACT_PREPDEL } xrootd_cms_node_action_t;
/* plan adds: const char *reqid, *notify, *prty;  (path already present) */

/* cms/node_ops.c — xrootd_cms_node_plan() */
case K_PREPADD:
    if (!field_str(d->path,d->path_len) || !field_str(d->reqid,d->reqid_len))
        return -1;
    plan->action = XRDCMS_NACT_PREPADD;
    plan->path   = (const char *) d->path;
    plan->reqid  = (const char *) d->reqid;
    plan->notify = field_str(d->notify, d->notify_len);
    plan->prty   = field_str(d->prty,   d->prty_len);
    return 0;
case K_PREPDEL:
    if (!field_str(d->reqid,d->reqid_len)) return -1;
    plan->action = XRDCMS_NACT_PREPDEL;
    plan->reqid  = (const char *) d->reqid;
    return 0;

/* cms/recv.c — node dispatch (FRM wiring + CMS-reqid map, ADR-6 D-a) */
case CMS_RR_PREPADD: {
    xrootd_cms_rrdata_t d; xrootd_cms_node_plan_t pl;
    if (xrootd_cms_rrdata_parse(code, payload, plen, &d) != 0
        || xrootd_cms_node_plan(code, &d, &pl) != 0)
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "bad prepadd");
    if (ctx->conf->rootfd < 0 || !ctx->conf->frm.enable)
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "no FRM");

    /* confinement: the path must lie under an exported prefix (no escape) */
    if (!xrootd_cms_path_in_export(ctx->conf, pl.path))
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "denied");

    frm_req_view_t v;
    ngx_memzero(&v, sizeof(v));
    v.lfn      = pl.path;
    v.notify   = pl.notify;                          /* may be NULL */
    v.options  = FRM_OPT_STAGE;
    v.priority = pl.prty ? (int8_t) ngx_atoi((u_char*)pl.prty, ngx_strlen(pl.prty)) : 0;
    if (v.priority < -1) v.priority = -1; else if (v.priority > 2) v.priority = 2;

    char frm_reqid[XROOTD_FRM_REQID_LEN];
    if (frm_request_add(ctx->conf->frm.queue, &v, frm_reqid, sizeof(frm_reqid),
                        ctx->cycle->log) != NGX_OK)
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "stage refused");
    xrootd_cms_reqid_map_put(pl.reqid, frm_reqid);   /* ADR-6 D-a */
    return NGX_OK;                                    /* silent success (cmsd) */
}
case CMS_RR_PREPDEL: {
    xrootd_cms_rrdata_t d; xrootd_cms_node_plan_t pl;
    if (xrootd_cms_rrdata_parse(code, payload, plen, &d) != 0
        || xrootd_cms_node_plan(code, &d, &pl) != 0)
        return ngx_xrootd_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "bad prepdel");
    char frm_reqid[XROOTD_FRM_REQID_LEN];
    if (xrootd_cms_reqid_map_take(pl.reqid, frm_reqid, sizeof(frm_reqid)))
        (void) frm_request_delete(ctx->conf->frm.queue, frm_reqid, ctx->cycle->log);
    return NGX_OK;                                    /* idempotent, silent */
}
```
The CMS-reqid map is a tiny SHM spin+yield slot table (`cms/reqid_map.{c,h}`,
key=cms_reqid → frm_reqid, TTL = `frm.stage_ttl`), unit-tested like `rrdata`.

## D.2 Landing sequence (dependency-ordered PRs, flags, rollback)

| PR | Workstream | Depends on | Feature flag (default) | Rollback |
|---|---|---|---|---|
| PR-1 | **W1** usage/stats | — | none (pure new replies) | revert 2 cases |
| PR-2 | **W9** status/vnid/BaseFS | — | none | revert handlers |
| PR-3 | **W4** load meter | — | `xrootd_cms_load_weight 0` (off) | weight 0 = current behaviour |
| PR-4 | **W6** blacklist+admin | — | `xrootd_cms_blacklist_file` unset | unset file; admin is additive |
| PR-5 | **W3** dynamic location | PR (loc_cache shm) | `xrootd_cms_locate_window 0` (off) | window 0 = static-only (today) |
| PR-6 | **W2** staging | reqid_map shm | `xrootd_frm` (existing) | FRM off ⇒ prepadd→error (today) |
| PR-7 | **W5** selection breadth | W4 (scoring) | `xrootd_cms_affinity off` | flags off = single-source (today) |
| PR-8 | **W8** multi-replica | agg shm, forward.c | `xrootd_cms_fanout off` | off = redirect (today) |
| (W7 multi-tier) | → **phase-62** | — | — | — |

Every flag defaults to **current behaviour**, so each PR is a no-op until enabled
— the W0-style "prove the default unchanged" gate, here per workstream. Order puts
the zero-risk wins (PR-1/2/3/4) first and the cross-worker piece (PR-8) last.

## D.3 Observability (metrics + diag) per workstream

Add low-cardinality counters (enum in `metrics.h`, export per
`XROOTD_<TYPE>_METRIC_INC`; **no path/host labels** — INVARIANT #8):

| WS | counters |
|---|---|
| W1 | `cms_usage_replies`, `cms_stats_replies` |
| W2 | `cms_prepadd_ok/err`, `cms_prepdel_ok`, `cms_reqid_map_size` (gauge) |
| W3 | `cms_loc_hit/miss`, `cms_state_probe_sent`, `cms_have_cached`, `cms_loc_window_timeout` |
| W4 | `cms_load_report_total` (the vector goes to logs, not labels) |
| W5 | `cms_select_multi`, `cms_affinity_hit`, `cms_try_<reason>` (4 fixed reasons) |
| W6 | `cms_blacklist_entries` (gauge), `cms_blacklist_reload`, `cms_admin_drain` |
| W8 | `cms_fanout_ops`, `cms_fanout_partial_fail`, `cms_fanout_wait` |

`XROOTD_DIAG` cause/fix lines for the operator-facing failures: FRM disabled on a
prepadd, blacklist-file parse error, locate-window timeout, fan-out node timeout.
Dashboard surfaces the gauges (`reqid_map_size`, `blacklist_entries`) alongside
the existing CMS node table.

## D.4 Status

Plan body (§1) + Appendix A (skeletons) + B (wire/manifest/config/tests) +
C (W3/W8 SHM designs, drop-in W1) + D (corrected drop-in W2, landing sequence,
metrics) make every workstream implementable with its defaults-unchanged flag,
rollback, and counters defined. The two FRM/CMS impedance points (ADR-6 reqid
map; ADR-1 forward-vs-redirect for prepare) are the only non-obvious design calls
and are both resolved here.

---

# Appendix E — authoritative status matrix + cross-workstream interactions

## E.1 Every CMS opcode × role × status (single source of truth)

Status: ✅ shipped · 🟦 this phase (workstream) · ⏭ phase-62 · — n/a for role.
"Manager" = frames the manager accepts (server_recv); "Node" = frames a data node
accepts from its manager (recv.c).

| kYR_* (val) | Manager | Node | Notes |
|---|---|---|---|
| login (0) | ✅ | — | + sss xauth |
| chmod (1) | ✅ fwd-redirect | ✅ exec | node confined exec shipped |
| locate (2) | ✅ (static) / 🟦W3 (dynamic) | ✅ (sub-mgr) | W3 adds state→have cache |
| mkdir (3) | ✅ redirect | ✅ exec | |
| mkpath (4) | ✅ redirect | ✅ exec | |
| mv (5) | ✅ redirect | ✅ exec | |
| prepadd (6) | 🟦W2 (fwd) | 🟦W2 (→FRM) | reqid-map ADR-6 |
| prepdel (7) | 🟦W2 (fwd) | 🟦W2 (→FRM) | |
| rm (8) | ✅ redirect / 🟦W8 fan-out | ✅ exec | W8 = all replicas |
| rmdir (9) | ✅ redirect / 🟦W8 | ✅ exec | |
| select (10) | ✅ | ✅ | 🟦W5 multi-source/affinity |
| stats (11) | 🟦W1 (size-form) | — | full XML = follow-on |
| avail (12) | ✅ | — | |
| disc (13) | ✅ | ✅ | |
| gone (14) | ✅ | — | path deregister |
| have (15) | 🟦W3 (cache) | ✅ emit | manager dispatch new |
| load (16) | ✅ recv / 🟦W4 vector | — | W4 fills theLoad |
| ping (17) | ✅ | ✅ | |
| pong (18) | ✅ | — | |
| space (19) | ✅ | ✅ | |
| state (20) | 🟦W3 emit | ✅ answer | manager probe new |
| statfs (21) | ✅ | — | |
| status (22) | ✅ / 🟦W9 reset | ✅ / 🟦W9 | reset/staging bits |
| trunc (23) | ✅ redirect | ✅ exec | |
| try (24) | ✅ recv | ✅ recv | 🟦W5 reasons/list |
| update (25) | ✅ | ✅ | |
| usage (26) | 🟦W1 (→load) | — | |
| xauth (27) | ✅ | — | sss |
| (meta routing manVOps) | ⏭W7 | — | multi-tier |

Net: after this phase only **W7 (multi-tier)** and the **full `stats` XML blob**
remain unhandled; every other opcode is wired on the role(s) that use it.

## E.2 Cross-workstream interactions (where the workstreams touch)

These are the non-obvious couplings a reviewer must hold in mind; each is benign
if respected:

1. **W3 ↔ W8 share `xrootd_srv_locate_all`.** W3 uses it to pick state-probe
   candidates; W8 uses it to pick fan-out targets. Keep it side-effect-free
   (pure read of the registry snapshot) so both can call it concurrently from
   different workers. Already pure today — don't add caching inside it (cache
   lives in W3's loc table).
2. **W4 ↔ W5 selection scoring order.** W4 introduces a load weight; W5 adds
   affinity. Define the precedence explicitly: **(a) freshness/blacklist filter
   (existing) → (b) affinity stick if `cms_affinity` and the sticky target is
   eligible → (c) score = space/util ± load_weight·load.** Affinity must *not*
   override the blacklist (a drained host is never sticky).
3. **W3 ↔ W2 via `CMS_HAVE_ONLINE`.** A `have` with `online=0` means "known but
   needs stage." A locate that resolves to an `online=0` location should trigger
   W2 `prepadd` (stage-in) rather than an immediate redirect — the natural
   tape-recall path. Wire only once both W2 and W3 land (PR-6 after PR-5).
4. **W8 ↔ Plane-B redirect (shipped).** Single-replica mutations stay on the
   redirect path; W8 engages only when `locate_all` returns >1 holder **and**
   `cms_fanout` is on. The mutation gate (`dispatch_write.c`) chooses: 0 holders →
   error; 1 → redirect; >1 + fanout → aggregate. Don't double-handle.
5. **All SHM tables share INVARIANT #10.** registry (existing), W3 loc cache, W8
   agg, W2 reqid-map — every one created via `xrootd_shm_table_mutex_create`
   (spin+yield), never stock `ngx_shmtx_create(…, NULL)`. A single grep gate in
   CI: no `ngx_shmtx_create` outside `compat/shm_slots.c`.
6. **W6 blacklist file ↔ runtime blacklist.** The file is *additive* over the
   30 s disconnect blacklist; a host can be in both. `undrain` clears only the
   runtime one — a file-listed host stays excluded until removed from the file
   (document this so operators aren't surprised).
7. **W1 `usage`/`stats` ↔ W4 load.** `usage` reports the same `load6` vector W4
   computes; ship W4 first (PR-3) or `usage` reports zeros until then (harmless,
   documented in the matrix).

## E.3 Saturation note

The plan now covers, for every workstream: rationale + severity (§0–1), code
skeletons (A), byte-exact wire + change manifest + config + tests (B), full SHM /
cross-worker designs for the hard pieces + drop-in W1 (C), corrected drop-in W2 +
landing sequence + metrics (D), and the authoritative opcode matrix + interaction
hazards (E). The two non-obvious design calls (ADR-1 forward-vs-redirect for
prepare; ADR-6 CMS↔FRM reqid map) are resolved. Further expansion would restate
existing sections rather than add design — the next step is **implementation**
(start at PR-1/W1, the drop-in in C.3), not more document.
