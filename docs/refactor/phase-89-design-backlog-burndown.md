# Phase 89 — design-backlog burndown: phase-60 Ceph namespace plane · phase-61 CMS parity implementation · phase-64 long tail

**Status:** COMPLETE 2026-07-21 (code + tests + docs; everything below is the
per-workstream record). Remaining follow-ups only: B's live Docker legs are
infra-blocked (daemon down, `xrd-ceph-build` image missing) and D.1's ADR-3
ratify awaits OP confirmation. — Workstream A (doc truth sweep) **DONE
2026-07-21**;
**B (Ceph namespace plane) CODE-COMPLETE 2026-07-21** (unit tests + build green;
live Docker legs written but blocked: Docker daemon down on this host, so the
phase-60 close-out doc sweep stays pending live verification);
**D.1 DONE 2026-07-21** (ratify recommended; grammar frozen by
`tests/test_frm_directive_pin.py`, 3 green — OP confirmation still pending);
**C: PR-1 (W1) DONE** (usage→load 13-byte golden + stats size-form + pre-auth
neg, `tests/test_cms_wire_pup_conformance.py` green) and **PR-2 (W9) DONE
2026-07-21** (status reset/suspend/resume/stage handler reading the modifier at
`ctx->inbuf[5]`; registry `vnid[64]`/`stage` fields + `brix_srv_reset`/
`_set_vnid`/`_set_stage`; login envCGI `vnid=` parse; node-side `brix_cms_vnid`
directive → envCGI emission; dashboard cluster rows gain `vnid`/`stage`;
4 new wire tests, file 31/31 green. BaseFS fast-exists: already satisfied —
the node-side state probe is stat-only via `brix_stat_beneath`, no code needed).
**PR-3 (W4) DONE 2026-07-21**: new `src/net/cms/meter.{c,h}` — pure `/proc`
parsers (loadavg/meminfo/net-dev/vmstat) + rate meter (125 MB/s net ref,
100 majfaults/s pag ref), all-zeroes-valid state, failures degrade to 0 (never
a failed heartbeat); standalone `meter_unittest.c` (gcc line in header) green;
node heartbeat now sends real cpu/net/mem/pag + dsk=util_pct (xeq always 0);
usage replies sample a per-srv-block meter; manager captures
`max(non-dsk bytes)` → registry `load_pct` (snapshot + dashboard `load_pct`
field); `brix_cms_load_weight` (0–100, clamped, default 0 = byte-identical
legacy scoring) blends load into selection via `srv_sel_load_metric` —
read: `((100-w)*util + w*load)/100`, write: `free_mb` scaled down by
`w*load/10000`; new wire test asserts live non-zero mem byte, all ≤ 100;
file 32/32 green, grammar `-t` green.
**PR-4 (W6′) DONE 2026-07-21**: new `src/net/cms/blacklist_file.{c,h}` —
`brix_cms_blacklist_file` directive (CMS-server srv conf, unset = off); one
`host`, `host:port`, or IPv4 `a.b.c.d/n` line each (bracketed/bare IPv6 host
text supported for exact match; interior whitespace = malformed → warn+skip,
never crash; 128-entry / 64 KB caps logged).  Poll piggybacks the per-conn
ping tick (self-rate-limited stat 1/s) + a force poll right after each
registration (brix_srv_register clears blacklists — the file re-covers it
before anything can be selected); blacklist duration = 3× ping interval, so
re-assert always outruns expiry and the FILE WINS over admin undrain, while
removing a line lifts the ban within ≤3 intervals.  Deliberate deviation from
the sketch: NOT hooked on the health-check manager timer (it doesn't run with
`brix_health_check off`); the ping tick always runs while nodes are
registered, which is exactly when the file matters.  Limitation (documented):
servers registered ONLY via the admin REST API with zero live CMS node
connections are not re-covered until some node logs in.  Tests:
`tests/test_cms_blacklist_file.py` (new template
`nginx_cms_blfile_server.conf`, CMS wire login + anonymous dashboard
`draining` observable) — CIDR-drained-at-registration / mtime edit picked up /
malformed lines skipped while good line applies / file wins over authorized
admin undrain; 4 green + wire file still 32 green; `check_vfs_seam.sh` green
(stat/fopen carry `vfs-seam-allow` operator-config markers).
**PR-5 (W3) DONE 2026-07-21**: dynamic location — loc cache + `kYR_state`
fan-out + `kYR_have` ingest, default-off (`brix_cms_locate_window 0` =
byte-identical).  New `src/net/manager/loc_cache.{c,h}`: SHM path→host:port
cache (fnv1a open-addressing, 256 slots, lazy 30 s TTL) via
`brix_shm_table_alloc` (INVARIANT #10), zone appended LAST in
`postconf_shared_registries` (zone order is the reload contract).  Locate leg
(`locate_try_dynamic` in `locate.c`): with the window on, cache hit →
immediate `kXR_redirect`; miss → park the client FIRST (existing pid-keyed
pending table, streamid from a `0x80000000|seq` per-worker generator so it
can never collide with the parent-leg ids), then fan `kYR_state` out to ≤
`brix_cms_state_fanout` (default 8) of this worker's logged-in node
connections whose export prefixes cover the path and that aren't
drained/blacklisted; 0 probes sent → unpark + fall through to the unchanged
prefix-select chain.  ORDERING DECISION: the dynamic leg runs BEFORE registry
prefix-select — file-granular truth beats prefix guessing (with common `r /`
exports prefix-select would always hit and make W3 dead code).  First
`kYR_have` wins: manager-side ingest (`cms_srv_frame_have`, new
`CMS_RR_HAVE` route) caches the location and wakes the parked session via the
now-shared `brix_cms_wake_pending_session` (refactored out of the parent
kYR_redirect path — one wake/redirect/resume implementation for both ingest
directions); later HAVEs are cache-only.  Window expiry reuses the EXISTING
`XRD_ST_WAITING_CMS` timeout in `connection/recv.c` verbatim: `kXR_wait 5` +
resume — zero new timeout code.  SECURITY GATE: a node may only assert
`have` for paths under its own login-Paths prefixes (new
`brix_srv_paths_cover` wrapper over the registry's longest-prefix matcher) and
drained/blacklisted nodes' HAVEs are refused (`brix_srv_is_blacklisted`) so
the dynamic plane cannot bypass the W6′ blacklist or an admin drain.  Fan-out
scope is per-worker (new node-list accessors in `server_handler.c`, add on
login-complete / swap-with-tail del on close); cross-worker aggregation is
PR-8's plane.  Tests: `tests/test_cms_locate_have.py` (template
`nginx_cms_locate_have.conf` — TWO listeners: `brix_cms_server on` replaces
the stream handler for its whole server block, so the CMS plane needs its own
port) — have-wins-redirect + second locate served from loc cache with no
re-probe / window expiry → `kXR_wait` and the connection stays usable /
hostile `have` outside the node's exported paths dropped+logged, never cached;
3 green + full CMS gate green (wire 32, blacklist-file 4, state/have/select,
manager-mode = 76 passed).  INVARIANT-#10 grep gate landed with this PR as
mandated: `tools/ci/check_shm_mutex.sh` (no bare `ngx_shmtx_create` outside
`shm_slots.c`) wired into `guards.yml` + README (pre-push globs it
automatically); tree clean.
**PR-6 (W2) DONE 2026-07-21**: forwarded staging — node-side `kYR_prepadd`/
`kYR_prepdel` per App C-2.  Planner: `node_ops.{c,h}` grew
`XRDCMS_NACT_PREPADD/PREPDEL` + plan `reqid/notify/prty` fields (prepdel is
routed BEFORE the primary-path guard — it carries only ident+reqid); 4 new
planner unit tests, standalone unittest green.  ADR-2b sidecar:
`src/net/cms/reqid_map.{c,h}` — SHM slot table (512 slots, fnv1a
open-addressing, 24 h TTL, `brix_shm_table_alloc` per INVARIANT #10) mapping
the MANAGER's reqid → the registry-minted engine reqid + the notify/prty
padArgs the registry view has no columns for; SHM (not per-worker) because a
post-reconnect prepdel may arrive on a different worker's manager connection;
`take()` consumes by expiring the slot in place so probe chains stay intact;
zone appended LAST in `postconf_shared_registries`.  Executor:
`src/net/cms/recv_prepare.c` — prepadd = lexical path gate (absolute, no
`..`, < `BRIX_STAGE_LFN_LEN`) → `brix_stage_request_add` (lfn, requester_dn
= padArgs ident, tod_expire from `frm.stage_ttl`) → `reqid_map_put`; prepdel
= `reqid_map_take` → `brix_stage_request_delete`, idempotent; replies match
stock cmsd do_PrepAdd/do_PrepDel (silent success + silent no-op delete,
`kYR_error` only for refused/undecodable prepadd).  Dispatch: two rows in
`cms_frame_table` (recv_frame.c) → thin `cms_frame_prepare` wrapper; decl in
recv_internal.h.  DEVIATION from the line-858 note: reqid_map has no
standalone unittest — SHM tables need the nginx runtime, so it is live-tested
through the wire suite; the pure planner logic is what got the unit tests.
Tests: `tests/test_cms_prepadd.py` (template `nginx_cms_prep_client.conf` =
state-client + `brix_frm`/control_dir; observable = the durable journal
`<control_dir>/stage_requests.dat` — prepadd makes the LFN bytes appear,
prepdel memzeroes the record so they vanish; query-prepare A/M output is
file-presence-based, not registry-backed, so the journal is the honest
observable): success (admit → scrub → idempotent re-del + ping), error
(truncated padArgs + reqid-less → "badly formed"; no-`brix_frm` node → "no
staging engine"), security-neg (`/../etc/stolen` and relative path →
"denied", never in the journal).  3 green; full CMS gate 66 passed (wire 32 +
blacklist-file + state/have/select + cms + fast-settle + locate-have +
prepadd); clean -Werror build + planner unittest green.
**PR-7 (W5) DONE 2026-07-21**: selection breadth.  Survey finding that shapes
the whole PR: in this topology clients speak XRootD to the manager and the CMS
*server* plane has no LOCATE/SELECT dispatch (`server_recv_frame.c` route
table), so W5's real emit surface is the root-plane locate/select path — not
CMS `kYR_try` frames.  Landed: (a) `brix_cms_affinity` (flag, default off) —
process-wide `brix_srv_set_affinity()` mirroring the W4 load-weight wiring
(`registry.c` global + `server_conf_merge_cluster.c` merge); in
`srv_select_core` the scan now collects every FRESH-tier candidate (bounded
`SRV_SEL_AFFINITY_MAX` 64) and, with affinity on and >1 candidate, the fnv1a
path hash — not the metric — picks the member.  LOCKED precedence (phase-61
note 2) holds structurally: blacklisted/stale slots never enter the fresh set,
so a drained host is never sticky, and an empty/singleton fresh tier keeps the
ladder winner.  (b) `brix_cms_locate_multi` (flag, default off) — the
manager-mode locate leg answers `kXR_ok` with the full live
`brix_srv_locate_all` "S<r|w>host:port" set (lateral redirect), placed before
the single-entry collapse cache; empty set falls through unchanged.  (c)
`CMS_TRY_*` sub-reason constants (YProtocol `kYR_try*` opts bits) added to
cms_internal.h as decode vocabulary.  DEVIATIONS from the phase-61 W5 note:
`kYR_try` list EMIT and `blredir` are not applicable here (our manager→parent
link sends raw-path `kYR_locate`, and no server-side select dispatch exists —
constants are vocabulary only); the doc's single `brix_cms_affinity` knob
became two (`+ brix_cms_locate_multi`) because sticky-redirect and full-set
replies are independent behaviours; "injected host in try-list rejected" is
covered by the existing registration choke (`brix_net_host_chars_valid` in
`brix_srv_register`) — the CMS-server plane derives host from the peer IP
(`ngx_sock_ntop`), so the wire-reachable hostile inputs are export scope and
drain state, which is what the security-neg tests.  Tests:
`tests/test_cms_affinity_multi.py` (template `nginx_cms_affinity.conf` — two
root listeners over one registry: sticky + multi): success (5× same-path
locate → one node, stable across sessions; multi lists both), error (drop
sticky node's CMS conn → blacklist → survivor selected, multi list shrinks),
security-neg ("r /data" node never listed outside its exports; every emitted
token matches strict `Sr<host>:<port>` grammar).  3 green; full CMS gate now
69 passed; clean -Werror incremental build (no new TUs).
**PR-8 (W8) DONE 2026-07-21**: rm/rmdir fan-out to all holders.  Grounding
finding that shaped v1: the node executor (`recv_forward.c`) is SILENT on
success and answers `kYR_error` only on failure, so positive acks cannot be
counted — aggregation is a deadline window (`brix_cms_fanout_window`, default
500ms): no node error inside it ⇒ `kXR_ok`; any error ⇒ `kXR_error` carrying
the first node's (printable-scrubbed) text; early-finalize when every
forwarded node errored.  New `src/net/cms/fanout.{c,h}` (per-worker slot
table keyed by the CMS streamid; client identity rides the shared
pending-locate table so the finalizer reuses the recycle-guarded wake shape of
`brix_cms_wake_pending_session`; `brix_cms_client_conn_by_fd` exported from
recv_frame.c instead of duplicating the lookup).  Hook: inside
`manager_redirect_mutation` (dispatch_write.c) before the single-node select;
NGX_DECLINED falls through to the shipped redirect.  Reply ingest: new
`CMS_RSP_ERROR` row in `cms_srv_frame_routes` (code 1 collides with
`CMS_RR_CHMOD` only as a request, which the manager plane never receives).
Directives `brix_cms_fanout` (off) + `brix_cms_fanout_window` (msec slot —
bare numbers are SECONDS, write `600ms`; a bare `600` armed a 10-minute
window and hung the client, the one real bug found live).  DEVIATIONS from
phase-61 App C.2: (a) per-worker aggregation, NOT the SHM agg table — fan-out
engages only when this worker's eligible logged-in CMS connections cover >=2
holders AND equal `brix_srv_count_matching(path)` (so a holder connected to
another worker, a single holder, or a drained holder ⇒ fall back to the
always-safe single-node redirect; a blacklisted holder still counts in the
registry total, deliberately blocking engage); (b) v1 scope is kXR_rm/kXR_rmdir
only (the G8 "rm-from-all-holders" motivator) — mv/chmod/trunc/mkdir keep the
redirect path.  Tests: `tests/test_cms_fanout_rm.py` (template
`nginx_cms_fanout.conf`): success (2-holder rm → both nodes receive `kYR_rm`
naming the path, client kXR_ok), error (one node replies `kYR_error` →
client kXR_error carrying "replica pinned"), security-neg (single holder →
kXR_redirect + zero forwards; "r /data" node never receives a delete outside
its exports).  3 green; full CMS gate 72 passed in 69.6s; clean -Werror build
(new TU ⇒ ./config + full configure re-run).
**Date:** 2026-07-21
**Scope:** the three "Design-only" items from the phase-88 open-work audit §5 —
**60** (Ceph beyond the basic driver), **61** (CMS parity), **64** (fully-tiered
composable storage + generic-slice-fill) — re-verified against the tree on
2026-07-21 and reduced to what is *actually* still open. This phase is the
implementation umbrella for that remainder, plus the documentation
reconciliation that closes the drift between those three design docs and the
landed code.
**Ground rule:** every claim below was verified against the tree (grep/read of
the named files), not taken from the source docs — all three docs pre-date the
`brix_` rebrand, the `src/frm/` dissolution, and the tier grammar, and all
three contained stale "still open" claims. Every code skeleton in the
appendices is grounded on **live signatures** quoted from the current headers
(cited per snippet), not on the source docs' pre-rebrand sketches.

> **Reading guide.** §0 verified baseline · §A doc sweep (done) · §B Ceph
> namespace plane · §C CMS parity execution · §D phase-64 long tail · §E
> effort/ordering · §F exit criteria · §Z ADRs · App A doc→tree symbol map ·
> App B §B skeletons · App C §C re-grounded skeletons (incl. the corrected W2
> drop-in) · App D test matrices · App E landing sequence.

---

## 0. Verified starting position (2026-07-21)

What the three source docs claim vs. what the tree holds. Each row names the
evidence file so a later reader can re-verify in one grep.

| Source doc | Doc's claim | Verified tree state | Evidence |
|---|---|---|---|
| `phase-60-ceph-rados-backend.md` | "still open: live routing, striper, dir listing, rename, xattr, staged commit" | **4 of 6 landed.** Routing: `tier_build.c` rados arm; `brix_storage_backend rados://pool` serves live. Xattr: 4 slots + `CAP_XATTR`/`CAP_XATTR_WRITE`. Staged: 4 `staged_*` slots. Striper: wrappers + lazy bind + stock layout. **Open: dir listing, rename** (+ marker decision). | `src/fs/tier/tier_build.c:267`; `src/fs/backend/rados/sd_ceph.c` descriptor (caps + slot table); `sd_ceph_striper.c`; `sd_ceph_io.c:53` (`sd_ceph_striper()` lazy bind); `tests/run_rados_parity.sh`; `tests/cmdscripts/ceph_operator.py` (`ceph_export_smoke`) |
| `phase-61-cms-parity.md` | plan/spec, not started | **Confirmed untouched** — with ONE exception the doc could not know: the **W6 admin surface already exists** (drain/undrain/delete/register cluster endpoints, see §C.1 W6 re-scope). Everything else open: no `USAGE`/`STATS`/`PREPADD`/`PREPDEL` dispatch; manager `kYR_have` undispatched; no `loc_cache`/`meter`/`blacklist_file`/`forward_agg` files. | `server_recv_frame.c:385-396` (`cms_srv_frame_routes[]` — no USAGE/STATS/HAVE/STATE rows); `recv_frame.c:375-389` (node table — no PREPADD/PREPDEL rows); `src/observability/dashboard/api_admin_cluster.c` (the landed admin surface) |
| `phase-64-fully-tiered-composable-storage.md` | design, five sub-projects | **Substantially landed:** §3 matrix closed, `src/frm/` dissolved → `stage_engine*`/`stage_request_registry*`/`stage_waiter*` + `sd_frm*`; `tape://`/`frm://` tier schemes; tape REST + root:// open gate drive the engine. **Divergence:** `brix_frm_*` directives survived contra §13c step 4. | `src/fs/xfer/` listing; `src/fs/backend/frm/` listing; `vfs_backend_config_ceph.c:328-351` (`tape://`/`frm://` parse); `tape_rest.c` (4 `brix_stage*` call sites); `open_request.c:512` ("former frm_stage_kick → engine step"); `directives_net.inc:204-267` (`brix_frm*` directives live) |
| `phase-64-generic-slice-fill.md` | BACKLOG (both items) | **Both items landed.** Group-2 strict-xfails now pass; read-fill admission actively tested. | `tests/test_cache_partial_fill.py:121` ("Formerly a strict xfail"), `:153` (`test_admission_prefix_regex_gating`, active); `src/fs/cache/writethrough_decision.c:2` (`cache_admit.h` "shared admission filter (read+write parity)") |

Net remaining work = **B** (phase-60 namespace plane, ~2–2.5 wk) + **C**
(phase-61 CMS parity, ~8.5 wk in flag-gated PRs — W6 shrank) + **D**
(phase-64 long tail, mostly small or infra-blocked). A (doc reconciliation)
executed with this doc.

---

## A. Doc truth sweep — DONE 2026-07-21

Applied per the phase-88 lesson (stale claims corrected in place with
SUPERSEDED blockquotes; the chronologically-last status section is the truth):

1. `phase-64-generic-slice-fill.md` — status flipped BACKLOG → **DONE**, with
   the verification pointers (which tests now pass and where the admit filter
   lives).
2. `phase-60-ceph-rados-backend.md` — SUPERSEDED blockquote under the status
   header correcting the "still open" list to *dir listing + rename + markers*
   and pointing here (§B).
3. `phase-64-fully-tiered-composable-storage.md` — status note recording the
   landed state, the `brix_frm_*` directive-grammar divergence (§13c step 4
   was **not** executed as written — the directives survived as engine/adapter
   knobs), and a pointer here (§D).
4. `phase-61-cms-parity.md` — top note: implementation tracked here (§C), and
   the W2/ADR-6 substrate correction (`frm_request_*` →
   `brix_stage_request_*`, §C.0).
5. `phase-88-open-work-audit.md` §5 — the "Design-only" sentence now points at
   this phase as the verified burndown.

**On completion of each workstream below, the same sweep repeats:** B closes →
update phase-60's header to "COMPLETE" + this doc's §B; C closes → update
phase-61 (per-PR, the E.1 opcode matrix cells flip 🟦→✅) + this doc's §C;
D items close → phase-64 §3/§13c + this doc's §D. Exit criterion §F.4 makes
the final sweep a hard gate — no phase-89 workstream is "done" until its
source doc says so.

---

## B. Phase-60 remainder — the Ceph/RADOS namespace plane (~2–2.5 wk)

The data plane, credentials, striper and staged writes are done. What is left
is exactly the flat-key-namespace → hierarchical-listing adapter the phase-60
doc designed in its §6 (stripe-collapse listing) and §7 (slot mapping), plus
two small follow-ons. All work lands in `src/fs/backend/rados/` behind the
existing `BRIX_HAVE_CEPH` gate; **no VFS or protocol changes** — the VFS
already degrades absent namespace slots, and the `maybe_cred` wrappers
(`brix_sd_opendir_maybe_cred`, `brix_sd_rename_maybe_cred`, `sd.h:727/:877`)
already handle the new slots' credential dispatch for free once the driver
fills them.

### B.0 Live contracts this builds on (verified 2026-07-21)

```c
/* sd.h — the vtable slots to fill (already declared, driver leaves them NULL): */
brix_sd_dir_t *(*opendir)(brix_sd_instance_t *inst, const char *path, int *err_out);
ngx_int_t      (*readdir)(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t      (*closedir)(brix_sd_dir_t *d);
ngx_int_t      (*rename)(brix_sd_instance_t *inst, const char *src, /* sd.h:391 */
                         const char *dst, int noreplace);

/* sd.h:283 — one directory entry: */
typedef struct { char name[256]; } brix_sd_dirent_t;
/* sd.h:335 — the dir handle shell: { brix_sd_instance_t *inst; void *state; } */

/* The enumeration substrate ALREADY SHIPPED (sd_ceph_cred.c, CAP_CATALOG): */
ngx_int_t sd_ceph_enumerate(brix_sd_instance_t *inst, int want_stat,
                            brix_sd_catalog_cb cb, void *ctx);
/* sd.h:255 — per-object callback payload:
 *   { const char *key; const char *path;      // path NULL ⇒ orphan candidate
 *     int have_stat; off_t size; time_t mtime; } */

/* Caps to add on completion (sd.h:94-108):
 *   BRIX_SD_CAP_DIRS (1u<<8)          — real directories (B.1)
 *   BRIX_SD_CAP_DIRS_WRITE (1u<<14)   — only if B.3 chooses marker objects
 * NOT added: BRIX_SD_CAP_HARD_RENAME (1u<<7) — B.2 rename is copy+delete,
 * non-atomic by design (same posture as s3/http). */
```

### B.1 Directory listing (`opendir`/`readdir`/`closedir` + `CAP_DIRS`) · ~1 wk

**Design (stripe-collapse over `enumerate` — phase-60 §6, re-grounded):**

- New TU `src/fs/backend/rados/sd_ceph_dir.c` (source-size guard — the driver
  is already split across 5 TUs); declarations in `sd_ceph_internal.h`;
  registered in repo-root `./config` (`NGX_ADDON_SRCS` — new-`.c`-file rule,
  full `./configure` re-run required, see the
  `concurrent_session_build_contention` / `build_source_list_location`
  gotchas).
- `sd_ceph_opendir(inst, path, err_out)`:
  1. Normalise + confine `path` with the existing `sd_ceph_normalize()` pure
     helper (unit-tested in `sd_ceph_unittest.c`); refuse escapes with
     `*err_out = EACCES`.
  2. Run one bounded `sd_ceph_enumerate(inst, /*want_stat=*/0, collect_cb,
     &snap)` collecting **logical `path`s** (not raw keys — the enumerate
     already recovers logical paths; `path == NULL` orphans are skipped for
     listing purposes).
  3. **Collapse to one level:** for each recovered path with the requested
     prefix, emit only the first component after the prefix; a component that
     has a `/` remainder is a synthetic subdirectory (mark `is_dir`), else a
     file entry.
  4. **Striper-shard suppression:** entries whose *key* matches the
     libradosstriper shard pattern (`<soid>.%016x` numbered shards — the
     first shard `.0000000000000000` *is* the logical object; shards ≥ 1 and
     the striper's lock/attr sentinel objects are suppressed). The pure
     match helper lives beside the layout helpers in `sd_ceph_compat.c`
     (already the home of "pure striper-layout helpers (catalog enumeration)")
     so `sd_ceph_unittest.c` covers it standalone against recorded
     stock-XrdCeph key fixtures.
  5. Sort + dedupe the collapsed set (the enumerate is unordered; POSIX
     consumers expect stable iteration), store as a compact snapshot in the
     handle state, return the `brix_sd_dir_t` shell.
- `sd_ceph_readdir(d, out)`: copy the next snapshot name into
  `out->name` (256-byte cap — longer names were already rejected by the key
  map); return the driver-standard end-of-stream code (match the posix
  driver's contract exactly — copy it, don't invent).
- `sd_ceph_closedir(d)`: free the snapshot.
- **Bounds (fail-closed, no unbounded memory):** snapshot capped by a
  compile-time entry ceiling (default 64 Ki entries) + a byte ceiling;
  exceeding either aborts the enumerate (`cb` returns non-zero) and fails the
  opendir with `E2BIG` + one `[warn]` — never a truncated-but-"complete"
  listing (the no-silent-caps rule).
- `opendir_cred` (`sd.h:543`): same body over the cred-scoped ioctx (the
  per-user conn cache from `sd_ceph_cred.c` already provides it) so a
  per-user CephX listing stays scoped to that user.
- Advertise `BRIX_SD_CAP_DIRS`. Free consumers, zero new protocol code:
  `kXR_dirlist`, WebDAV PROPFIND depth-1, S3 ListObjects (all ride the VFS
  dir seam), **and the phase-64 `cstore_scan` eviction walk for a rados cache
  store** (§D.2 collapses into this).

**Effort split:** shard-suppression pure helper + unit fixtures 1.5 d ·
opendir/readdir/closedir + cred variant 2 d · caps flip + live validation
1.5 d.

### B.2 Rename (copy+delete) · ~0.5 wk

- `sd_ceph_rename(inst, src, dst, noreplace)` in `sd_ceph_object.c`:
  1. `noreplace` honoured by a `dst` existence stat first (racy-by-nature on
     an object store — documented, same as s3).
  2. Copy **striper-aware**: if the source resolves through the striper
     (probe the same way the read path does), copy via striper read →
     striper write so the destination keeps the stock-compatible layout;
     plain objects copy via `rados_read`/`rados_write_full` loop with the
     existing io-chunk bound.
  3. Copy the object xattrs (cinfo/meta/lock ride along — required for the
     phase-64 cache-store role to survive a rename).
  4. Delete the source **only after** a successful dst fstat verify —
     mid-copy failure leaves the source intact (no destructive first step).
- `rename_cred` (`sd.h:520`) same body over the cred ioctx.
- **No `CAP_HARD_RENAME`** — non-atomic is honest and the VFS/protocol layers
  already treat it as such for s3/http.
- Collection (directory) rename stays refused (`EISDIR`): flat namespace, the
  recursive-child-lock invariant #5 machinery would otherwise need a
  key-prefix mass move — out of scope, documented.

### B.3 Dir markers (`mkdir` semantics) — decision + ~2 d

Flat key namespaces have no empty dirs. Either
- **(a)** the phase-60 §10 `ceph_dir_markers` directive: zero-length marker
  objects (suppressed from B.1 listings), `mkdir`→ create marker, `rmdir` →
  delete marker iff prefix empty; adds `CAP_DIRS_WRITE`; or
- **(b)** synthetic dirs (the S3 model): `mkdir` = confined no-op success,
  `rmdir` of a non-empty prefix `ENOTEMPTY`, listing shows only non-empty
  prefixes; no new writable control surface.

**ADR-1 (provisional): (b).** Markers add a writable surface to every mkdir
for cosmetic value; nothing in the fleet round-trips empty dirs on rados.
Confirm at pickup; if a workflow surfaces (e.g. WebDAV MKCOL-then-PUT clients
that verify the MKCOL), flip to (a) — the listing suppression hook from B.1
already accommodates markers.

### B.4 Harness + docs · ~2 d

- `tests/run_rados_parity.sh` (env-gated `BRIX_TEST_RADOS_POOL`) gains: a
  listing-parity leg (same logical tree on posix vs rados export, `xrdfs ls`
  output identical), a **stock-interop leg** (write via stock XrdCeph
  striper, list + rename via brix, re-read via stock), and a rename leg.
- `tests/test_ceph_live.py` (Docker demo-RADOS lab,
  `PHASE81_RUN_CEPH_PORTS=1`) gains the same three against the live
  container, plus the 3-per-change security-negs (App D.1).
- Close out phase-60: header → COMPLETE via SUPERSEDED block (§A rule).

### B.5 File/function change manifest

| File | Add / modify |
|---|---|
| `src/fs/backend/rados/sd_ceph_dir.c` | **new** — opendir/readdir/closedir (+`_cred`), snapshot state |
| `src/fs/backend/rados/sd_ceph_compat.c` | + striper-shard match helper (pure, unit-tested) |
| `src/fs/backend/rados/sd_ceph_object.c` | + `sd_ceph_rename`/`_rename_cred` |
| `src/fs/backend/rados/sd_ceph_internal.h` | + declarations, dir-state struct |
| `src/fs/backend/rados/sd_ceph.c` | descriptor: wire 5–7 new slots, add `CAP_DIRS`; refresh the (already-stale) "deliberately absent" comment |
| `src/fs/backend/rados/sd_ceph_unittest.c` | + shard-suppression + collapse fixtures |
| repo-root `./config` | + `sd_ceph_dir.c` (→ full `./configure` re-run) |
| `tests/run_rados_parity.sh`, `tests/test_ceph_live.py` | + B.4 legs |
| `docs/refactor/phase-60-…md`, this doc | close-out sweep |

---

## C. Phase-61 CMS parity — implementation (~8.5 wk, flag-gated PRs)

The phase-61 doc is implementation-ready to the byte level and **stays the
design authority**: gap inventory §0, wire layouts App B, SHM designs App C
(W3 location cache, W8 cross-worker aggregation), corrected W2 drop-in App D,
opcode matrix App E. This phase **executes** it. The corrections below are
recorded once, here, and applied while coding — not re-derived per PR.

### C.0 Design-refresh deltas (verified; apply before PR-1)

**C.0.1 — W2 substrate: the FRM request API is gone.** The doc routes
forwarded `prepadd`/`prepdel` into `frm_request_add/_delete`. `src/frm/` was
dissolved by phase-64 P6; the live API is the stage-engine request registry
(`src/fs/xfer/stage_request_registry.h`):

```c
brix_stage_registry_t *brix_stage_registry_singleton(void);   /* NULL = engine off */
ngx_int_t brix_stage_request_add(brix_stage_registry_t *reg,
    const brix_stage_request_view_t *view, char *reqid_out, …);
ngx_int_t brix_stage_request_owner_check(brix_stage_registry_t *reg,
    const char *reqid, …);
ngx_int_t brix_stage_request_delete(brix_stage_registry_t *reg,
    const char *reqid, ngx_log_t *log);
/* view = { lfn (required); requester_dn; user; cs_type; cs_value; tod_expire } */
```

Reference consumer: `src/protocols/root/query/prepare.c:314–402` (the doc's
own pointer, already migrated — `owner_check` before `delete`, `add` with a
zeroed view). Three consequences:

1. **ADR-6 D-a survives, retargeted.** The registry mints its own reqids
   (`"<seq>.<pid>@<host>"`, wire-frozen — `BRIX_STAGE_REQID_LEN 64`) exactly
   as FRM did, so the CMS-reqid → engine-reqid sidecar map is still the right
   shape. Zero engine-core change.
2. **`notify`/`prty` have no registry home.** The old `frm_req_view_t`
   carried notify/priority; `brix_stage_request_view_t` does **not** (the
   engine scheduler is FIFO + reaper). Resolution (**ADR-2b**): the CMS
   sidecar map stores them alongside the engine reqid
   (`{cms_reqid → engine_reqid, notify[…], prty}`); `notify` is honoured by
   the CMS layer on completion-poll (v1: recorded but un-fired, matching the
   engine's current no-callback model — the honest option), `prty` recorded
   for a future scheduler knob. Extending the engine view is explicitly
   rejected (touches the frozen durable record for a field the engine cannot
   yet act on).
3. **Prep-status queries** (`query prepare` reflecting W2 state) read
   `brix_stage_request_t.status`
   (`QUEUED/ACTIVE/DONE/FAILED/CANCELLED`) — richer than the old FRM view;
   the W2 tests assert against these states.

**C.0.2 — W6 admin surface: half of it already exists.** The doc planned
dashboard endpoints for drain/undrain/list (its ADR-2). The tree already has
them: `api_admin_cluster.c` serves
`/brix/api/v1/admin/cluster/servers/{host}/{port}/drain|undrain|delete` +
`register` (upsert), authenticated + fail-closed
(`api_admin.c:485 admin_route_cluster_server`), and
`/brix/api/v1/cluster` serves the registry listing
(`module_dispatch.c:82`). **W6 therefore shrinks to the file-driven blacklist
only** (~0.5 wk, was 1 wk) — plus one paragraph in the admin-API docs tying
drain semantics to the blacklist-file semantics (interaction #6 in phase-61
App E.2: `undrain` clears only the runtime entry; a file-listed host stays
excluded until the file changes).

**C.0.3 — Naming.** Every phase-61 skeleton is pre-rebrand. The verified
doc→tree symbol map is **Appendix A**; each PR's first step is re-grounding
its snippets on it. The dispatch idiom also changed shape: opcodes are not a
`switch` but flat route tables — server side
`cms_srv_frame_routes[] = {{CMS_RR_LOGIN, cms_srv_frame_login}, …}`
(`server_recv_frame.c:385`), node side the equivalent table +
`brix_cms_route_lookup(XRDCMS_ROLE_NODE, code)` (`recv_frame.c:375/419`).
**A new opcode = one `{code, handler}` row + one static handler function** —
smaller diffs than the doc's switch-case sketches.

### C.1 PR sequence

Unchanged from phase-61 App D.2 except W6's re-scope — every flag defaults to
current behaviour, so each PR is a provable no-op until enabled. Full
dependency/rollback table in **Appendix E**.

| PR | WS | What | Effort | Flag (default = today) |
|---|---|---|---|---|
| PR-1 | W1 | `usage`→`kYR_load` / `stats` size-form replies (App C.1 here) | 0.5 wk | none (new replies) |
| PR-2 | W9 | `status` reset/staging transitions, `vnid` login passthrough, BaseFS fast-exists | 0.5 wk | none |
| PR-3 | W4 | real load vector (`/proc` meter) + load-weighted selection | 1 wk | `brix_cms_load_weight 0` |
| PR-4 | W6′ | file-driven blacklist (mtime re-read → `brix_srv_blacklist`) | **0.5 wk** | `brix_cms_blacklist_file` unset |
| PR-5 | W3 | dynamic location: manager `state` probe → `have` dispatch → TTL'd SHM loc cache | 1.5 wk | `brix_cms_locate_window 0` |
| PR-6 | W2 | prepare/staging: node `prepadd/prepdel` → stage-request registry (App C.2 here); manager forward per ADR-1 | 1.5 wk | engine present (existing gate) |
| PR-7 | W5 | multi-source `kYR_try` lists, affinity/Pack, try-reasons, `blredir` | 1.5 wk | `brix_cms_affinity off` |
| PR-8 | W8 | multi-replica mutation fan-out: SHM aggregation + per-worker forward | 1.5 wk | `brix_cms_fanout off` |
| — | W7 | multi-tier (supervisor/meta-manager/ManTree) | 3–4 wk | **stays split out** (phase-61 ADR-4: its own phase) |

Registry primitives every PR builds on (all live, `src/net/manager/registry.h`):
`brix_srv_locate_all` (:193 — W5 multi-source + W8 fan-out targets, keep it
side-effect-free), `brix_srv_select_or_blacklisted` (:166 — note: part of the
doc's W5 "tried/triedrc convergence" concern is already handled here; W5
re-checks what remains), `brix_srv_aggregate_space` (:203 — W1),
`brix_srv_snapshot` (:212 — W3 probe candidates), `brix_srv_blacklist`/
`brix_srv_undrain` (:98/:102 — W6′), `brix_cms_forward_to_node`
(`forward.h:32` — W2/W8 wire primitive, already unit-tested).

### C.2 Per-PR notes beyond the doc (only the deltas)

- **PR-1 (W1):** drop-in is App C.1 here (re-grounded from phase-61 App C.3).
  New rows in `cms_srv_frame_routes[]`; reply builder in `server_send.c`
  using `ngx_brix_cms_put16/_put_int` (`wire.c:44/:77`). `usage` reports
  zeros in the 5 non-dsk load bytes until PR-3 lands (harmless, per phase-61
  E.2 interaction #7); `dsk` byte = util from `brix_srv_aggregate_space`.
- **PR-2 (W9):** reset → a registry clear helper (new, beside
  `brix_srv_unregister`); vnid = login-payload passthrough into
  `brix_srv_entry_t` (struct grows → **clean rebuild**, the
  `struct_field_abi_clean_rebuild` gotcha); BaseFS fast-exists = stat-only
  probe short-circuit in the W3 path (lands as a stub now, wired by PR-5).
- **PR-3 (W4):** new `src/net/cms/meter.{c,h}` (pure `/proc` parsers get a
  standalone `meter_unittest.c` like `rrdata`/`router`); vector consumed by
  `send.c` heartbeat (`theLoad` bytes) + `registry_select.c` scoring behind
  `brix_cms_load_weight` (0 = byte-identical current scoring).
- **PR-4 (W6′):** new `src/net/cms/blacklist_file.{c,h}`; mtime poll from the
  existing low-rate manager timer (no new thread/timer); each line
  host[:port] or CIDR → `brix_srv_blacklist(host, port, /*permanent*/1)`;
  file entries re-asserted after `undrain` (the file wins — document it).
- **PR-5 (W3):** phase-61 App C.1 is the design of record (SHM open-addressing
  loc table, TTL-lazy-evict, bounded state fan-out + collection window,
  first-`have`-wins wake). Two tree bindings: the SHM shell via
  `brix_shm_table_alloc` + the spin+yield mutex creator
  (`src/core/compat/shm_slots.h` — INVARIANT #10, never bare
  `ngx_shmtx_create`); client parking via the existing pid-keyed pending
  table (`src/net/manager/pending.h`). Security gate unchanged: a node may
  only assert `have` for paths under its login-Paths prefixes (validate
  against its registry entry before caching).
- **PR-6 (W2):** App C.2 here is the corrected drop-in (supersedes phase-61
  App D.1 which targets the deleted FRM API).
- **PR-7 (W5):** multi-source list from `brix_srv_locate_all`; affinity =
  `hash32(path) % eligible` stick behind `brix_cms_affinity`;
  `kYR_try*` sub-reason constants per `YProtocol.hh`
  (`/tmp/brix-src/src/XProtocol/`); precedence LOCKED as: blacklist/freshness
  filter → affinity (only among eligible) → score (space/util ± load). A
  drained host is never sticky.
- **PR-8 (W8):** phase-61 App C.2 design of record (SHM agg table keyed by
  manager streamid, origin pid+fd+conn-generation finalizer resolution —
  same recycle-guard as the pending wake path). v1 simplification stands:
  each worker forwards on the node connections *it* owns (every node conn
  lives on exactly one worker ⇒ the fan-out is covered with no inter-worker
  posting). Engages only when `locate_all > 1` holder AND `brix_cms_fanout
  on`; single-replica stays on the shipped redirect path (no double-handle —
  E.2 interaction #4).

### C.3 Cross-cutting gates (enforced per PR)

- All new SHM tables (loc cache, agg, reqid map) via the `brix_shm_table_*`
  helpers — spin+yield, never bare `ngx_shmtx_create` (INVARIANT #10; the
  phase-61 CI grep gate comes with PR-5).
- `brix_srv_locate_all` stays a pure registry-snapshot read (W3 + W8 call it
  concurrently from different workers).
- Security-negs are first-class in every PR (App D.2 matrix): hostile `have`
  for a non-exported prefix not cached; prep path export-confined
  (`../escape` refused); try-list hosts from the registry only; blacklist
  file parse failures skip-the-line, never crash.
- Metrics per phase-61 App D.3 (low-cardinality only — INVARIANT #8; no
  path/host labels), `BRIX_DIAG` cause/fix lines for the operator-facing
  failures.
- Regression gate per PR: the existing CMS suites stay green
  (`test_cms_wire_pup_conformance.py`, `test_manager_mode.py`,
  `test_cms_state_have_select.py`, + `rrdata`/`router`/`node_ops` unit TUs);
  golden byte-exact frames added for every new opcode/reply (wire layouts:
  phase-61 App B.1 — unchanged, the wire is the wire).
- New `.c` files (`meter.c`, `blacklist_file.c`, `loc_cache.c`,
  `forward_agg.c`, `reqid_map.c`) → repo-root `./config` → full
  `./configure` re-run each time.

---

## D. Phase-64 long tail

The umbrella spec's own §3/§13c/§14 status blocks + this tree-check say what
is left. Four items, two classes.

### D.1 Decision required — `brix_frm_*` directive grammar (~2 d after the call)

Phase-64 P2/§13c-step-4 specified deleting the `brix_frm_*` directives in
favour of `tape://` store-URL params. The tree kept them — the full live set
(`src/protocols/root/stream/directives_net.inc:204–267`):

| Directive | Owner after dissolution |
|---|---|
| `brix_frm` | engine enable (gates `conf->frm.enable` consumers, e.g. `open_request.c:481`, `tape_rest.c`) |
| `brix_frm_queue_path` | engine durable-journal dir |
| `brix_frm_max_inflight` / `_max_per_source` | engine scheduler bounds |
| `brix_frm_stagecmd` / `_copycmd` / `_copymax` | exec MSS adapter (`sd_frm_exec.c`) |
| `brix_frm_stage_ttl` / `_xfrhold` / `_stage_wait` | engine park/reap timing (`open_request.c:508/:520/:526`) |

Resolve explicitly:
- **(a) ratify** — amend phase-64 §13c step 4 to "directives retained as
  engine/adapter knobs"; document each knob's owner (table above goes in the
  phase-64 doc + operator docs); optionally alias the misleading `frm` name
  (`brix_stage_*`) later, low priority; or
- **(b) finish the migration** — adapter knobs (`stagecmd`/`copycmd`/
  `copymax`) fold into `tape://<adapter>?…` URL params, queue/timing knobs
  become `brix_stage_*` directives, old names → `[emerg]` with a pointer.

**ADR-3 recommendation: (a).** The knobs configure the *engine and adapter*,
which survived the dissolution as first-class subsystems; renaming
operator-visible directives is churn without a correctness payoff, and P2's
"no legacy" was aimed at the *cache* grammar (which WAS deleted, §14 status
block). Whichever way: one config-grammar pin test
(`nginx -t` matrix over the knob set) locks the outcome. **Needs OP
confirmation before the phase-64 close-out.**

### D.2 Object-store eviction scan — **absorbed into §B.1**

`cstore_scan` needs a walk over object stores with no `opendir`. B.1 gives
rados real `opendir/readdir` over `enumerate` — nothing further to build for
rados. If s3/http cache-store eviction at scale is ever needed, repeat the
same adapter shape there (ListObjectsV2 / PROPFIND depth-1); not scheduled
until a deployment runs an s3-backed cache store big enough to evict.

### D.3 Serve off-load beyond `xroot` — explicitly deferred

curl-backed (s3/http) and in-process (rados) backends serve inline,
blocking-but-completing on the worker; only the socket-wire `xroot` driver
uses the thread-pool serve off-load
(`src/protocols/shared/http_serve_offload.c`). Latency-fairness optimisation,
no correctness gap. Defer until a profile shows worker stall under mixed
load; pickup is a generalisation of the existing off-load, not new design.

### D.4 HPSS/CTA native MSS adapters — infra-blocked (parked)

The `exec` stagecmd adapter (`sd_frm_exec.c`) covers the generic HSM
contract; native adapters need vendor libraries unavailable in this
environment. Parked with the phase-88 §4 infra-blocked register. The adapter
vtable (`sd_frm_mss.h`) is the stable seam — no design work remains, only the
vendored builds + a lab.

### D.5 Phase-64 §21 open questions — resolve-on-touch

cinfo-xattr vs sidecar batching (measure when a remote cache store deploys in
anger); remote stage-journal durability beyond the object write; RADOS
credential representation in the credential block (note: the per-user CephX
keyring path landed via `ucred.c` — partially answers it); recall progress
for `kXR_wait` hints. Each is answered inside whichever workstream first
touches it; none blocks B/C/D.

---

## E. Effort & ordering

| Order | Work | Effort | Why this order |
|---|---|---|---|
| 1 | A doc truth sweep | done | shrinks the visible backlog to what is real |
| 2 | B Ceph namespace plane (B.1→B.2→B.3→B.4) | 2–2.5 wk | self-contained; closes phase-60 AND the D.2 eviction gap in one move |
| 3 | D.1 directive-grammar decision | 2 d | pure decision + one pin test; unblocks the phase-64 close-out narrative |
| 4 | C phase-61 PR-1…PR-8 | ≈8.5 wk | the one large item; quick wins (PR-1/2/3/4 ≈ 2.5 wk) land value first |
| — | C/W7 multi-tier | 3–4 wk | its own future phase (phase-61 ADR-4 stands) |
| — | D.3, D.4, D.5 | — | deferred / infra-blocked / resolve-on-touch |

Total scheduled: **≈ 11.5 wk** engineering to clear every non-parked item
from the phase-88 "Design-only" line.

## F. Exit criteria

1. **B done:** rados driver advertises `CAP_DIRS`; listing/rename/marker
   semantics green in the parity script (incl. the stock-XrdCeph interop
   leg) **and** the live Docker lab; phase-60 doc header reads COMPLETE.
2. **C done:** phase-61 App E.1 opcode matrix shows every 🟦 cell ✅ (W7 cells
   stay ⏭); all flags exist with defaults preserving pre-phase behaviour
   (each PR proven a no-op with its flag off); CMS suites + new golden
   frames green; the INVARIANT-#10 grep gate in place.
3. **D done:** D.1 resolved by an OP-confirmed ADR in phase-64 + the
   config-grammar pin test; D.2 absorbed (B.1); D.3/D.4/D.5 carried as
   explicit parked/deferred entries in the phase-88 register (no silent
   drops).
4. **Doc gate (hard):** each workstream's source doc (60/61/64 + this one +
   the phase-88 audit) is updated **in the same change** that completes the
   workstream — the sweep in §A is the template. A workstream whose source
   doc still claims it is open is not done.

## Z. ADR log

- **ADR-1:** rados directories are synthetic (no marker objects) unless a
  real workflow needs empty-dir round-trips (§B.3 — provisional, confirm at
  B.3 pickup; the B.1 suppression hook accommodates a flip).
- **ADR-2:** phase-61 W2 keeps the ADR-6 **D-a** sidecar reqid map,
  retargeted at the stage-request registry; **ADR-2b:** `notify`/`prty`
  (absent from `brix_stage_request_view_t`) live in that sidecar map, not in
  the engine's frozen durable record (§C.0.1).
- **ADR-3:** `brix_frm_*` directives — recommendation is
  ratify-as-engine-knobs (§D.1a); **requires OP confirmation** before the
  phase-64 close-out.
- **ADR-4 (inherited):** phase-61 W7 multi-tier remains split into its own
  future phase; nothing here depends on it.
- **ADR-5:** rename on rados is copy+delete without `CAP_HARD_RENAME`;
  directory rename refused (§B.2) — parity with the s3/http drivers'
  posture, not a regression.

---

# Appendix A — phase-61 doc→tree symbol map (verified 2026-07-21)

Apply mechanically when lifting any phase-61 appendix snippet. "≈" = same
role, different shape (see note).

| Phase-61 doc symbol | Live tree symbol | Where |
|---|---|---|
| `xrootd_cms_srv_ctx_t` | `brix_cms_srv_ctx_t` | `cms/server.h:38` |
| `xrootd_cms_srv_send_frame` | `brix_cms_srv_send_frame` | `server_send.c:14` |
| `xrootd_cms_srv_send_data` / `_send_status` / `_send_error` | `brix_cms_srv_send_*` family | `server_send.c` |
| `ngx_xrootd_cms_put16` / `_put_int` / `_put_string` | `ngx_brix_cms_put16` / `_put_int` / `_put_string` | `wire.c:44/:77/:92` |
| `cms_srv_process_frame` switch-cases | ≈ rows in `cms_srv_frame_routes[]` + a `cms_srv_frame_<op>()` handler | `server_recv_frame.c:385` |
| node `recv.c` dispatch cases | ≈ rows in the node route table + `cms_frame_<op>()`; routing flags in `router.c` (`K_*` table) | `recv_frame.c:375`, `router.c` |
| `xrootd_cms_rrdata_t` / `rrparse` | `brix_cms_rrdata_t` / `brix_cms_rrdata_parse` | `rrdata.h` (`padArgs`/`pdlArgs` decode shipped) |
| `xrootd_cms_node_plan` / `node_ops.h` enum | `brix` node planner; enum values keep the `XRDCMS_NACT_*` prefix (add `_PREPADD`/`_PREPDEL` after `_TRUNC`) | `node_ops.h:23-31` |
| `xrootd_cms_forward_to_node` | `brix_cms_forward_to_node` | `forward.h:32` |
| `xrootd_srv_aggregate_space` | `brix_srv_aggregate_space(uint32_t *total_free_mb, …)` | `manager/registry.h:203` |
| `xrootd_srv_locate_all` | `brix_srv_locate_all` | `registry.h:193` |
| `xrootd_srv_snapshot` | `brix_srv_snapshot` (+ `brix_srv_snapshot_entry_t`) | `registry.h:212/:62` |
| `xrootd_srv_blacklist` / undrain | `brix_srv_blacklist` / `brix_srv_undrain` | `registry.h:98/:102` |
| — (not in doc) | `brix_srv_select_or_blacklisted` — pre-existing tried/triedrc convergence; W5 builds on it | `registry.h:166` |
| `xrootd_shm_table_alloc` / mutex create | `brix_shm_table_*` | `core/compat/shm_slots.h:76` |
| `xrootd_pending_lookup/remove/unlock` | `brix` pending table | `manager/pending.h` |
| `frm_request_add(q, frm_req_view_t*, …)` | **`brix_stage_request_add(reg, brix_stage_request_view_t*, reqid_out, …)`** — reg = `brix_stage_registry_singleton()`; view lost `notify`/`selector`/`options`/`priority`/`queue` (ADR-2b) | `fs/xfer/stage_request_registry.h:104` |
| `frm_request_delete(q, reqid, log)` | `brix_stage_request_delete(reg, reqid, log)` (+ `_owner_check` first) | `:130/:119` |
| `XROOTD_FRM_REQID_LEN` | `BRIX_STAGE_REQID_LEN` (64, wire-frozen `"<seq>.<pid>@<host>"`) | `:36` |
| dashboard admin `api_admin.c` endpoints (W6) | **already landed**: `/brix/api/v1/admin/cluster/servers/{h}/{p}/drain\|undrain\|delete`, `register`, `/brix/api/v1/cluster` listing | `api_admin_cluster.c`, `api_admin.c:485`, `module_dispatch.c:82` |
| directives `xrootd_cms_*` | new directives take `brix_cms_*` (house style per `server.h:12` `brix_cms_server`) | `cms/config.c` / `server_module.c` |

# Appendix B — §B skeletons (Ceph namespace plane)

## B-1. Stripe-collapse listing (`sd_ceph_dir.c`)

```c
/* dir-handle state (sd_ceph_internal.h) */
typedef struct {
    char   **names;        /* sorted, deduped, collapsed one-level entries */
    ngx_uint_t count, pos;
    /* backing arena freed as one block in closedir */
} sd_ceph_dir_state_t;

/* collect callback fed to the SHIPPED enumerator */
typedef struct {
    const char *prefix;  size_t prefix_len;     /* normalized listing dir + "/" */
    /* bounded accumulator: cap entries/bytes; overflow ⇒ return non-zero */
} sd_ceph_dir_collect_t;

static int
sd_ceph_dir_collect(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    sd_ceph_dir_collect_t *c = ctx;

    if (ent->path == NULL) return 0;                    /* orphan: not listable */
    if (sd_ceph_striper_shard_key(ent->key)) return 0;  /* shard n>0 / sentinel:
                                                           suppressed (B.1.4)  */
    if (strncmp(ent->path, c->prefix, c->prefix_len) != 0) return 0;

    /* collapse: first component after the prefix; '/' in the remainder ⇒ a
     * synthetic subdirectory entry (emit once — dedupe on insert) */
    …
    return 0;   /* non-zero only on the entry/byte ceiling ⇒ opendir E2BIG */
}

brix_sd_dir_t *
sd_ceph_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    /* 1. sd_ceph_normalize(path) — refuse escape (EACCES)
     * 2. sd_ceph_enumerate(inst, 0, sd_ceph_dir_collect, &c)   — one pass
     * 3. sort + dedupe into sd_ceph_dir_state_t; wrap in brix_sd_dir_t shell */
}
/* readdir: copy next name into out->name (brix_sd_dirent_t, 256B) — return the
 * exact end-of-stream contract the posix driver uses (copy, don't invent).
 * closedir: free the arena. *_cred twins run over the cred-scoped ioctx from
 * the sd_ceph_cred.c connection cache. */
```

`sd_ceph_striper_shard_key()` is a **pure** helper in `sd_ceph_compat.c`
(beside the existing layout helpers), covered in `sd_ceph_unittest.c` against
recorded stock-XrdCeph key fixtures: the `.%016x` numbered shards (shard 0 =
the logical object → NOT suppressed as a *key*, but the listing works on
recovered logical paths so shard naming never leaks upward), the striper
lock/attr sentinels, and plain (non-striped) keys.

## B-2. Rename (`sd_ceph_object.c`)

```c
ngx_int_t
sd_ceph_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
               int noreplace)
{
    /* 1. normalize both; noreplace ⇒ stat(dst) first (documented racy)      */
    /* 2. copy striper-aware: source striped (probe as the read path does) ⇒
     *      striper read → striper write (keeps stock layout on dst);
     *    else rados_read → rados_write_full chunk loop (existing io bound)  */
    /* 3. copy xattrs (cinfo/meta/lock must survive — phase-64 cache-store)  */
    /* 4. fstat-verify dst (size match) BEFORE rados_remove(src) — mid-copy
     *    failure leaves src intact; cleanup dst temp on abort               */
    /* dirs: EISDIR (flat namespace; collection rename refused, ADR-5)       */
}
```

# Appendix C — §C re-grounded skeletons

## C-1. PR-1 / W1 drop-in (usage → load; stats size-form) — live names

Wire layout unchanged from phase-61 App B.1 (byte-exact: `usage` reply =
`hdr{code=16(kYR_load)} payload[13] = 00 06 | load6 | a0 <free_mb u32BE>`).

```c
/* cms/server_send.c */
ngx_int_t
brix_cms_srv_send_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const uint8_t load6[6], uint32_t free_mb)
{
    u_char p[16], *c = p;
    ngx_brix_cms_put16(c, 6);  c += 2;
    ngx_memcpy(c, load6, 6);   c += 6;
    c = ngx_brix_cms_put_int(c, free_mb);
    return brix_cms_srv_send_frame(ctx, streamid, CMS_RR_LOAD, 0,
                                   p, (size_t) (c - p));      /* dlen = 13 */
}

/* cms/server_recv_frame.c — two new handlers + two route rows */
static ngx_int_t
cms_srv_frame_usage(brix_cms_srv_ctx_t *ctx, uint32_t sid, u_char mod,
                    const u_char *payload, size_t plen)
{
    uint32_t free_mb = 0, util = 0;
    uint8_t  load6[6] = {0};                 /* PR-3 fills; zeros = parity   */
    if (!ctx->logged_in) return NGX_OK;      /* pre-auth: ignore             */
    brix_srv_aggregate_space(&free_mb, &util);
    load6[5] = (uint8_t) (util > 100 ? 100 : util);
    return brix_cms_srv_send_load(ctx, sid, load6, free_mb);
}
static ngx_int_t
cms_srv_frame_stats(…)                        /* size-only form (kYR_size)  */
{ u_char b[4]; … ngx_brix_cms_put32-equiv …; return brix_cms_srv_send_data(ctx, sid, b, 4); }

/* the table (server_recv_frame.c:385) gains:
 *   { CMS_RR_USAGE, cms_srv_frame_usage },
 *   { CMS_RR_STATS, cms_srv_frame_stats },                                  */
```

## C-2. PR-6 / W2 corrected drop-in (supersedes phase-61 App D.1)

Node side — forwarded `prepadd`/`prepdel` → the stage-request registry.
`rrdata` already decodes `padArgs`/`pdlArgs`; the planner grows two actions.

```c
/* cms/node_ops.h — enum grows after XRDCMS_NACT_TRUNC: */
    XRDCMS_NACT_PREPADD, XRDCMS_NACT_PREPDEL
/* plan gains: const char *reqid, *notify, *prty;  (path already present)    */

/* cms/recv_frame.c — two route rows + one handler pair. Dispatch body: */
case-equivalent PREPADD handler:
    brix_stage_registry_t *reg = brix_stage_registry_singleton();
    if (reg == NULL)
        return ngx_brix_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "no engine");
    if (!brix_cms_path_in_export(ctx->conf, pl.path))       /* confinement  */
        return ngx_brix_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "denied");

    brix_stage_request_view_t v;                 /* live view — C.0.1        */
    ngx_memzero(&v, sizeof(v));
    v.lfn          = pl.path;                    /* required                 */
    v.requester_dn = ctx->peer_ident;            /* node's manager identity  */
    /* NB: view has NO notify/prty (ADR-2b) — they go in the sidecar map     */

    char engine_reqid[BRIX_STAGE_REQID_LEN];
    if (brix_stage_request_add(reg, &v, engine_reqid,
                               sizeof(engine_reqid), …) != NGX_OK)
        return ngx_brix_cms_send_error(ctx, sid, CMS_ERR_EINVAL, "refused");
    brix_cms_reqid_map_put(pl.reqid, engine_reqid, pl.notify, pl.prty);
    return NGX_OK;                               /* silent success (cmsd)    */

PREPDEL handler:
    char engine_reqid[BRIX_STAGE_REQID_LEN];
    if (brix_cms_reqid_map_take(pl.reqid, engine_reqid, sizeof(engine_reqid)))
        (void) brix_stage_request_delete(reg, engine_reqid, log);
    return NGX_OK;                               /* idempotent, silent       */
```

The sidecar map `cms/reqid_map.{c,h}` is a small `brix_shm_table_*`
spin+yield slot table: key = cms_reqid → `{engine_reqid[64], notify[…],
prty}`, TTL = the engine reap horizon; standalone-unit-tested like `rrdata`.
Manager side per phase-61 ADR-1 (forward to holders, not redirect) —
rendezvous with PR-8 for multi-holder. Status queries read
`brix_stage_request_t.status` (QUEUED/ACTIVE/DONE/FAILED/CANCELLED).

## C-3. Pointers for the hard pieces (design-of-record unchanged)

- **W3 loc cache:** phase-61 App C.1 verbatim, with `brix_shm_table_alloc` +
  spin+yield mutex (`shm_slots.h`) and the `manager/pending.h` park/wake.
- **W8 aggregation:** phase-61 App C.2 verbatim (SHM agg keyed by manager
  sid; origin pid+fd+conn-generation finalize; v1 = each worker forwards its
  own node conns).
- **W4 meter / W5 selection / W9:** phase-61 App A.4/A.5/A.8 with the App-A
  symbol map applied.

# Appendix D — test matrices (3-per-change: success · error · security-neg)

## D.1 Workstream B (Ceph namespace)

| Item | success | error | security-neg |
|---|---|---|---|
| B.1 listing | `xrdfs ls` parity posix-vs-rados over the same logical tree; striper-written pool lists one entry per logical object | snapshot ceiling exceeded → `E2BIG` opendir, `[warn]`, no truncated listing | enumerate confined to the export prefix (no cross-namespace key leak from the shared pool); `..` in the listing path refused |
| B.1 cred | per-user CephX listing serves under that user's ioctx | cred keyring unreadable → open error, no fallback to service cred | user A's listing never uses user B's cached conn (pin/refcount audit) |
| B.2 rename | byte-exact + xattrs carried; striper layout preserved on dst | mid-copy failure ⇒ src intact, dst temp cleaned | rename across the export prefix refused; `noreplace` honoured |
| B.3 (ADR-1b) | mkdir no-op-success inside export; rmdir non-empty → `ENOTEMPTY` | — | mkdir outside the export refused |
| B.4 interop | stock-XrdCeph write → brix list+rename → stock re-read | — | — |

## D.2 Workstream C (CMS) — phase-61 App B.5 carried over, W6′ re-scoped

| PR | success | error | security-neg |
|---|---|---|---|
| PR-1 | usage→13-byte load frame; stats→size form (golden bytes) | malformed query frame dropped | pre-auth usage/stats ignored |
| PR-2 | reset clears node state; vnid round-trips login | unknown status modifier → no-op | — |
| PR-3 | non-zero load vector in heartbeat; score shifts under load with weight>0 | `/proc` read failure → zeros, no crash | — |
| PR-4 | file-listed host never selected; mtime edit picked up | malformed line skipped (logged) | file wins over `undrain` (re-asserted) |
| PR-5 | state probe → have → cache → redirect; O(1) second locate | no have in window → NotFound (or static fallthrough) | hostile `have` for a foreign prefix not cached/served |
| PR-6 | prepadd → registry row (QUEUED); prepdel removes; query prepare reflects status | bad reqid → `kYR_error`; engine off → error | `../escape` prep path refused (confined) |
| PR-7 | N-server try ordering (golden); affinity sticky across opens | all-tried → NotFound, no loop | injected host in try-list rejected (registry allowlist); drained host never sticky |
| PR-8 | rm clears both replicas of a 2-replica file | one node errors → first/worst to client; deadline → `kYR_wait` | forwarded op still export-confined on each node |

Per-PR regression gate: the existing CMS suites green + flag-off no-op proof
(run the suite with the PR's flag at default, diff behaviour = none).

## D.3 Workstream D

| Item | test |
|---|---|
| D.1 | config-grammar pin: `nginx -t` matrix over the ratified/migrated knob set (outcome-dependent) |
| D.2 | covered by B.1 (rados cache-store eviction walk exercisable via `cstore_scan`) |

# Appendix E — §C landing sequence (dependency-ordered, flags, rollback)

| PR | Depends on | New files (→ `./config` + re-`./configure`) | Flag (default) | Rollback |
|---|---|---|---|---|
| PR-1 W1 | — | — | none | revert 2 route rows + 1 builder |
| PR-2 W9 | — | — | none | revert handlers (registry-entry field ⇒ clean rebuild both ways) |
| PR-3 W4 | — | `cms/meter.{c,h}` + unittest | `brix_cms_load_weight 0` | weight 0 = current scoring |
| PR-4 W6′ | — | `cms/blacklist_file.{c,h}` | `brix_cms_blacklist_file` unset | unset = no file layer |
| PR-5 W3 | shm zone | `manager/loc_cache.{c,h}` | `brix_cms_locate_window 0` | window 0 = static-only (today) |
| PR-6 W2 | reqid-map shm | `cms/reqid_map.{c,h}` + unittest | engine-present gate (existing) | engine off ⇒ prep error (today) |
| PR-7 W5 | PR-3 (scoring) | — | `brix_cms_affinity off` | flags off = single-source (today) |
| PR-8 W8 | agg shm, forward.c | `cms/forward_agg.{c,h}` | `brix_cms_fanout off` | off = redirect (today) |

New directives are `brix_cms_*` `ngx_command_t` rows beside the existing
`brix_cms_server_*` set; defaults all preserve today's behaviour, so every PR
is a provable no-op until its flag is enabled — the per-PR "flag-off suite
diff = none" proof in App D.2 is the gate.
