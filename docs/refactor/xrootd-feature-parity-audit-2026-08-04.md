# XRootD → BriX full feature-parity audit — 2026-08-04

Source of truth: seven parallel source-level audits of `/tmp/xrootd-git-src` (upstream
XRootD, all of `src/`) vs this repo, one per subsystem. Every status line below was
grep/read-verified in BOTH trees (the repo's own older comparison docs were NOT trusted —
several stale rows in them are corrected here, see §9.6).

Scope rule (owner directive): BriX must eventually support **all** XRootD features
EXCEPT (a) the dynamic plugin architecture (`.so` loading seams — the features plugins
deliver ARE in scope, compiled-in) and (b) the binary monitoring streams
(`xrootd.monitor` f/r/g-streams, mpxstats UDP summary relay — Prometheus/unified
metrics is the accepted substitute). Those two are marked EXCLUDED and are never
counted as gaps.

Legend: **PRESENT** (functional parity or superset) · **PARTIAL** (works, named
sub-behavior missing) · **MISSING** · **N/A-ARCH** (concern dissolved by the nginx
in-process architecture) · **EXTRA** (BriX-only, no upstream equivalent).

---

## 0. Executive summary

BriX is far closer to full parity than a subsystem count suggests. The core wire
protocol (all 33 opcodes incl. pgwrite CSE recovery, chkpoint, fattr, clone, writev,
statx), GSI/krb5/sss/pwd/unix/ztn/host auth, request signing, xrdacc authdb, native +
HTTP TPC, the cmsd wire protocol (both halves, interop-tested against stock meshes),
FRM-equivalent staging/tape lifecycle, XCache-equivalent partial-file caching, SSI
server side, and a large client stack all exist and are mostly byte-faithful.

The genuinely missing feature bodies, ranked by size:

1. **Erasure coding (XrdEc)** — 0%, nothing anywhere.
2. ~~**Metalink**~~ — **LANDED 2026-08-09** (phase-100): client-side virtual
   redirector — v4/v3 parser (`client/lib/xfer/metalink.c`), any-transport
   document fetch, ranked mirror failover, document digest as integrity gate,
   `--no-metalink` opt-out (`tests/test_metalink.py`, `metalink_unit.c`).
3. ~~**Extreme copy (multi-source XCp) + real multi-stream data fan-out**~~ —
   multi-stream **LANDED 2026-08-04** (phase-94: bound-connection read+write
   data path, client fan-out default-on, `--parallel` striped download);
   extreme copy **LANDED 2026-08-09** (phase-100): `xrdcp --sources N`
   block-stealing engine over metalink mirrors / locate replicas
   (`client/lib/xfer/copy_xcp*.c`, `tests/test_extreme_copy.py`).
4. ~~**Multi-manager redundancy**~~ — **LANDED 2026-08-05**: `brix_cms_manager`
   takes up to 15 endpoints (multi-arg and/or repeated, duplicates rejected),
   the node logs into ALL of them concurrently, locates rotate round-robin
   over live links with automatic failover, CNS events fan out to every link
   (`tests/test_cms_multi_manager.py`).
5. **Background prefetch in the cache** (`pfc.prefetch`) + serve-while-filling
   whole-file mode + RAM tier (XrdRmc / `pfc.ram` / oss.memfile mmap/mlock).
6. **Space groups + generic quota** (`oss.space` multi-partition, `oss.cgroup`
   selection, usage/quota ledgers outside pblock; wire reports `oss.quota=-1`).
7. ~~**`sec.protbind` per-host auth policy + true multi-protocol sectoken** (one auth
   scheme per listener today; only ztn+gsi composes).~~
   **LANDED 2026-08-05** as a generic VFS engine (`src/auth/protbind/`) shared by
   both frontends: `brix_protbind` (stream) and `brix_webdav_protbind` (HTTP),
   with arbitrary ordered multi-protocol sectoken emission
   (`tests/c/protbind_test.c`, `tests/test_protbind_parse.py`).
8. ~~**Per-capability TLS gating** (`xrootd.tls login/session/data/tpc` bits)~~
   **LANDED 2026-08-05** as the generic VFS `brix_tls_require` mask (all four
   planes) + kXR_tls* advertisement + `brix_ztn_cleartext` stock-parity default
   (`src/fs/vfs/vfs_secgate.c`, `tests/test_tls_require.py`).
9. **OssArc dataset→zip tape aggregation**; **frm_purged tape-buffer purge policy**
   (explicitly scoped out at FRM dissolution — revisit).
10. **Client-side ecosystem holes**: ~~tried=/triedrc= never emitted~~ and
    ~~`--tpc delegate` hardcodes `tpc.dlgon=0`~~ both **LANDED 2026-08-09**
    (see §7.4/§7.5); still open — no byte-offset `--continue`, POSIX preload is
    a read-only shim (no write path, no readdir, no stdio family), xrootdfs has
    no multi-server fan-out / per-user sss identity, no fork-safety (no
    pthread_atfork), no `XRD_*` env compatibility.

**2026-08-09 fix wave** — full writeup in
[`phase-102-audit-fix-wave-2026-08-09.md`](phase-102-audit-fix-wave-2026-08-09.md)
(small audit items, one commit-sized batch; tests in
`tests/test_audit_fixes_2026_08_09.py` + `client/tests/c/kxr_errors_unit.c`):
§1.5 error constants · §4.2 `brix_cache_cold_max_age` · §4.4
`brix_cache_only_if_cached` · §5.2 signing no longer silently unenforced
(+`brix_signing_required`) · §7.4 tried=/triedrc= · §7.5 `--tpc delegate`.
§6.3 (TPC push egress) needed no work — that row was stale. Two defects found
while testing are folded in: the cache reaper reported unverified removals as
successes (§9.2), and the client refused the delegation round it advertised.

**2026-08-09 CMS + HTTP-redirect wave** (the bulk of the §2 residual table +
§6.1; tests in `tests/test_cms_parity_wave.py` (19 cases) +
`tests/test_webdav_redirect_ds.py` (7 cases)): §2.2 SUPCount floor
(`brix_cms_delay_servers`/`_delay_hold`) · §2.3 cms.sched component weights +
fuzz band + maxload (`brix_cms_sched`, `registry_select_sched.c`) · §2.5
stage-aware selection (`brix_cms_stage_select`) · §2.6 fxhold TTL + negative
location cache (`brix_cms_fxhold`/`_emptylife`) · §2.7 kXR_refresh cache
bypass · §2.8 shared-FS mode (`brix_cms_dfs`) · §2.9 ManTree login offload
(`brix_cms_server_max_direct` + login-kYR_try retarget) · §2.11 external load
feed (`brix_cms_perf_pgm`) · §2.12 foreign data server (`brix_cms_altds`
[monitor]) · §2.13 blacklist `*` patterns / per-entry `redirect` / whitelist
mode · §2.17 peer/proxy roles (`brix_cms_role peer|proxy`) · §6.1 HTTP
redirect-to-dataserver + `brix_http_secretkey` signed-CGI handoff
(`webdav/redirect.c`). Full stock ManTree tree-negotiation and the
byte-exact XrdHttp redirect-CGI hash are documented divergences (upstream
tree unavailable to verify either).

Also collected en route: a dead-code/doc-drift punch list (§9.6) including dormant
HTTP redirect-to-dataserver (implemented, zero call sites), TPC push skipping the
egress allowlist (known audit finding), throttle engines parsed-but-unwired, and two
stale claims in the repo's own feature-matrix docs.

---

## 1. Core wire protocol + XrdXrootd/XrdOfs server layer

Verified against `XProtocol.hh`, `XrdXrootdXeq*.cc`, `XrdXrootdConfig.cc`,
`XrdOfsConfig.cc`. BriX advertises protocol 0x520 (deliberate superset of the pinned
0x511 RFC doc, to carry kXR_clone).

**PRESENT (byte-faithful, spot list):** 20-byte hello + 12-byte legacy response; all
33 opcodes dispatched with kXR_Unsupported fallback; login/auth multi-round; endsess
(correct previous-session semantics); ping; set (incl. cms.space appid); sigver
secver-0 (session-cipher-encrypted SHA-256, stock XrdSecProtect) with seqno
replay guard + pedantic payload-coverage rule; bind with
capability-restricted secondaries; chmod/mkdir(+mkpath)/mv (incl. arg1len==0 quirk)/
rm/rmdir/truncate (dual fhandle/path mode); dirlist chunked streaming + kXR_dstat +
kXR_dcksm; stat ASCII body + kXR_vfs + vendor statNoFollow + handle-stat (invariant 7);
statx; locate (wildcard, Sx tokens, CMS/static-map/collapse-cache); open flag decode
single-sourced + kXR_retstat + posc + compress (vendor superset); POSC temp+fsync+
rename with disconnect unlink; read (sendfile/TLS split, AIO, kXR_wait backpressure);
readv (per-segment fhandle, 1024-seg cap); write/writev (+doSync, AIO); pgread 4007
framing + per-page CRC32c; **pgwrite full CSE recovery** (Fob corrupt-page ledger,
kXR_pgMaxEpr/Eos caps, cseCRC retransmit list, pgRetry exactly-one-page rule, close
blocked while uncorrected); sync; clone (32-byte items, copy_file_range, 1024 cap);
chkpoint all 5 subops + restart recovery; fattr del/get/list/set at spec limits +
vendor recurse; query: QStats/QPrep/Qcksum (async via waitresp, xattr-cached)/
Qckscan/Qxattr/Qspace/Qconfig/Qvisa (superset — stock has it commented out)/
QFinfo/QFSinfo (stock needs FSctl plugin)/Qopaque(uf) reference-compatible; prepare
stage/cancel/evict/notify/coloc/wmode/noerrs with durable FRM queue; kXR_wait /
waitresp / attn-asynresp / asyncms; kXR_status CRC header; errno→kXR mapping incl.
reference quirks (ENOTEMPTY→ItExists, EAGAIN-lock→FileLocked).

**Gaps (priority order, files to touch):**

| # | Gap | Status | Notes / where |
|---|-----|--------|---------------|
| 1 | **pathid response offloading** (do_Offload/do_OffloadIO parity): read/readv/write/pgread/pgwrite pathid decoded (`codec/wire_codec_file.c:161,189`) but no handler routes response data over bound streams; kXR_AnyPath too | PARTIAL | `connection/send.c`, `session/bind.c`, fd-table sharing — the one substantive data-path gap |
| 2 | pgread request args: pathid + `kXR_pgRetry` (client re-requests corrupt pages) | MISSING | `read/pgread.c` (no payload parse) |
| 3 | Login `ability`/`ability2` honored: kXR_fullurl, kXR_redirflags, hasipv64/onlyprv4/6 addr-family redirect variants, lclfile | MISSING (decoded, ignored) | store in ctx at `session/login.c`, branch `response/control.c` |
| 4 | kXR_protocol: `expect` byte not parsed; `kXR_bifreqs`+'B' ServerResponseBifs+`xrootd.bindif` absent; per-plane TLS bits (tlsData/tlsSess/tlsTPC/tlsGPF) never set; per-request secvec always 0 | PARTIAL/MISSING | `session/protocol.c` |
| 5 | ~~Missing error constants: kXR_SigVerErr(3022), DecryptErr(3023), BadPayload(3026), noReplicas(3029), ReqTimedOut(3034), TimerExpired(3035)~~ | **LANDED 2026-08-09** | Defined in `protocol/opcodes.h`, named in `core/compat/kxr_names.c`, mapped in `core/compat/error_mapping.c` (SigVer/Decrypt→EACCES, BadPayload→EINVAL, noReplicas→EHOSTUNREACH, both timeouts→ETIMEDOUT), and the three TRANSIENT ones (noReplicas/ReqTimedOut/TimerExpired) now classify RETRYABLE in the client (`status.c`) — a stock server's timeout used to abort the whole transfer. BriX's own sigver responses deliberately keep sending kXR_NotAuthorized (wire-compat with the locked `test_sigver_*` suites). Unit: `client/tests/c/kxr_errors_unit.c`. |
| 6 | stat `wants`/kXR_Want_btime extended mask; open `optiont` (retstatx/directio/dup/samefs) decoded-not-acted | MISSING | `read/stat.c`, open path |
| 7 | dirlist `kXR_online` filter masked out | MISSING | `dirlist/handler.c:45-47` |
| 8 | locate options refresh/nowait/4dirlist/compress parsed-then-discarded (`locate.c:87-91`); refresh must bypass loc/redir caches | PARTIAL | `read/locate.c` |
| 9 | POSC crash-orphan scrub at boot + `ofs.persist {auto|manual|off} [hold]` policy | PARTIAL | boot sweep in `fs/vfs/` |
| 10 | `xrootd.fsoverload` (stall n / redirect host / bypass) + `ofs.maxdelay` clamp as config policy | MISSING | stall seconds currently hardcoded |
| 11 | chkpoint `ofs.chkpnt maxsz` knob (cap fixed at kXR_ckpMinMax) | PARTIAL | `write/chkpoint.c` |
| 12 | prepare `prty` priority + UDP notify callback (`port`/kXR_usetcp); `xrootd.prep keep/scrub/logdir` | PARTIAL | in-band asyncms substitutes |
| 13 | QStats format: abbreviated counters, not stock XML `<statistics>` doc — XML-parsing clients fail | DIVERGENT | `query/util.c` |
| 14 | Qconfig key-for-key parity (bind_max, pio_max, readv_ior_max, sysid, wan_port, window…; unmatched keys must echo) | PARTIAL | `query/config.c` |
| 15 | Query-by-fhandle (do_Qfh Qcksum/Qxattr on open handle) | UNCONFIRMED/likely PARTIAL | `query/dispatch.c` keys on infotype only |
| 16 | XrdXrootdAdmin unix-socket admin (abort/cont/disc/msg/pause) | MISSING | no admin socket |
| — | kXR_gpfile | N/A-PARITY | stock returns kXR_Unsupported too |

---

## 2. Clustering (XrdCms / cmsd)

BriX: `src/net/cms/` + `src/net/manager/` + root-plane integration; in-process (no
separate cmsd, no ofs↔cmsd IPC — Admin socket/Finder/ClientMan/nbsendq are N/A-ARCH).
Wire-interoperable with stock cmsd (interop + Pup conformance + hostile suites).

**PRESENT:** manager/server/sub-manager roles with upward space aggregation; 4-tier
topologies tested; CmsRRHdr+Pup byte-exact codec; all 28 kYR opcodes; role-based
valid-ops routing tables (incl. meta-manager destructive-op prohibition); sss xauth
handshake (fail-closed w/ keytab); kYR_state fan-out + first-have-wins with client
parking; SHM loc cache + redirect-collapse cache; /proc load meter (real cpu/net/xeq/
mem/pag); three-tier select ladder (fresh>stale>blacklisted; reads=lowest util,
writes=highest free); path-hash affinity (≈weak); tried/triedrc convergence →
kXR_NotFound; zero-server → kXR_noserver honesty; forwarded namespace ops + rm/rmdir
fan-out to all holders; prepadd/prepdel with reqid map into stage registry; blacklist
file (host/host:port/CIDR, mtime reload) + runtime drain/undrain (EXTRA); CNS
inventory (EXTRA vs stock cmsd); active health probes of nodes (EXTRA); suspend/
resume via kYR_status; vnid; Cluster.Stats byte-exact vs 5.9.6.

**Gaps:**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | **Multiple managers**: `brix_cms_manager` rejects a second entry (`net/cms/config.c:20-22`), only `url.addrs[0]` used; stock logs into ALL managers + ClientMan rotation | **LANDED 2026-08-05** | up to 15 endpoints, concurrent logins (one heartbeat ctx per manager, disjoint streamid lanes), round-robin locate rotation + failover (`ngx_brix_cms_pick_ctx`), CNS fan-out to all links, duplicate endpoints rejected at parse; `tests/test_cms_multi_manager.py` |
| 2 | `cms.delay servers <n>` (SUPCount floor — don't serve until ≥n nodes registered; fresh manager with 1/20 nodes redirects everyone to it) + overload/hold/qdn/rw tunables | **LANDED 2026-08-09** | `brix_cms_delay_servers <n>` + `brix_cms_delay_hold <s>`: locate/open/stat answer kXR_wait(hold) while registered data servers (roles S/PS) < n (`registry_policy.c` `brix_srv_below_floor`, gated in `locate_manager.c`, `open_manager.c`, `stat_manager.c`); `tests/test_cms_parity_wave.py::test_floor_*` |
| 3 | cms.sched component weights (cpu/io/runq/mem/pag/space), fuzz round-robin band, maxload refusal, refreset/SelbyRef, gshr/gsdflt meta share | **LANDED 2026-08-09** | `brix_cms_sched cpu N io N runq N mem N pag N space N fuzz N maxload N`: per-component blend of the five raw theLoad bytes + disk util, fuzz-band round-robin, maxload demotes hot nodes to a last-resort tier (`registry_select_sched.c`, LOAD vector stored per entry). gshr/gsdflt meta share still open. `tests/test_cms_parity_wave.py::test_sched_*` |
| 4 | cms.space: configurable min (hardcoded 100MB), HWM re-eligibility hysteresis, linger, recalc, mwfiles | PARTIAL | `cms_internal.h:56` |
| 5 | **Stage-aware selection**: stage/nostage recorded (`registry.c:431-446`) but select never consults it; no "prefer holders, else stage on best-space node + kXR_wait" two-phase | **LANDED 2026-08-09** | `brix_cms_stage_select on`: a read of a file no node holds (loc-cache miss / negative entry) routes to the roomiest stage-capable node (`brix_srv_select_stage`, `registry_select_sched.c`; wired in `locate_manager.c` + `open_manager.c`); `tests/test_cms_parity_wave.py::test_stage_*` |
| 6 | cms.fxhold / cache TTLs: loc cache fixed 30s (stock default 8h, directive-driven); no negative location cache (noloc/emptylife) | **LANDED 2026-08-09** | `brix_cms_fxhold <t>` sets the positive loc-cache TTL; `brix_cms_emptylife <t>` adds a negative "no holder" entry written on a fan-out that expires with no kYR_have (`loc_cache.c` three-way `brix_loc_cache_lookup2`, `connection/recv.c` expiry site); `tests/test_cms_parity_wave.py::test_emptylife_*` |
| 7 | kXR_refresh locate must bypass caches (parsed, ignored) | **LANDED 2026-08-09** | `kXR_refresh` locate now flushes + bypasses both the loc cache and the collapse-redir cache and re-probes (`locate.c` decodes the bit, `locate_manager.c` invalidates via `brix_loc_cache_invalidate`/`brix_redir_cache_invalidate`); `tests/test_cms_parity_wave.py::test_refresh_bypasses_negative_cache` |
| 8 | cms.dfs shared-FS mode (central/distrib lookup, qmax, redirect immed/verify, mlevel) — shared-FS sites do redundant per-node probes | **LANDED 2026-08-09** | `brix_cms_dfs on`: skips the per-file kYR_state fan-out entirely (every node sees every file) and selects by load; `tests/test_cms_parity_wave.py::test_dfs_skips_state_fanout` |
| 9 | Dynamic supervisor machinery: superport, self-instantiation, ManTree auto-balancing (static config works today); ClustID/subcluster dedup; cidtag | **LANDED 2026-08-09** (offload) | `brix_cms_server_max_direct <n>`: past n direct data servers a new server login is answered kYR_try naming the least-utilised registered supervisor and closed; the node honors an unsolicited login kYR_try (`recv_frame.c` `cms_frame_login_retarget`, revert-on-failure). Full ManTree tree *negotiation* (superport self-instantiation, ClustID dedup) not byte-verifiable without an upstream tree — documented divergence. `tests/test_cms_parity_wave.py::test_max_direct_*` |
| 10 | Meta-manager selection semantics: cluster-granular ClustID masks, gshr weighting | PARTIAL | up/down legs + kYR_metaman stamp exist |
| 11 | cms.perf pgm external load feed (pgm form is NOT plugin) | **LANDED 2026-08-09** | `brix_cms_perf_pgm <cmd> [brix_cms_perf_interval <t>]`: a long-lived pipe-reader child (`perf_pgm.c`, posix_spawn + event-loop line parse, respawn-on-death) whose "cpu net xeq mem pag" lines override the /proc meter while fresh; `tests/test_cms_parity_wave.py::test_perf_pgm_overrides_meter` |
| 12 | cms.altds (advertise a foreign data server + liveness) | **LANDED 2026-08-09** | `brix_cms_altds <port> [monitor]`: the login advertises the foreign data port as dPort; the optional monitor (`altds.c`, nonblocking loopback probe) drives kYR_status suspend/resume on every link when the foreign DS dies/returns; `tests/test_cms_parity_wave.py::test_altds_*` |
| 13 | Blacklist: whitelist mode, `redirect <targets>` per-entry, `*` hostname patterns | **LANDED 2026-08-09** | `blacklist_file.c`: `*` host patterns (shared protbind NList matcher), per-entry `redirect <host:port>` answered as a login kYR_try, and `brix_cms_whitelist_file` (only listed hosts admitted; login refused otherwise); `tests/test_cms_parity_wave.py::test_blacklist_*` / `test_whitelist_*` |
| 14 | cms.allow netgroup/hostname-pattern forms | PARTIAL | CIDR only (blacklist/whitelist now take `*` patterns) |
| 15 | Request coalescing (XrdCmsRRQ batching N waiters on one lookup) | PARTIAL | per-client pending entries; 30s caches blunt it |
| 16 | kYR_try as "re-login to other managers" (honored only as pending-locate redirect) | **LANDED 2026-08-09** (login leg) | an unsolicited login kYR_try now re-dials the named manager (`cms_frame_login_retarget`, depth+failure bounded, reverts to the configured manager); the pending-locate kYR_try leg is unchanged |
| 17 | Peer/proxy CMS roles (9 stock roles vs 4) | **LANDED 2026-08-09** (peer/proxy) | `brix_cms_role peer\|proxy` login Mode bits + manager-side classification (roles "P"/"PS"); a peer is selected only as a last resort before NotFound, a proxy server is selectable normally (`send.c`, `server_recv_parse.c`, `registry_select.c`); `tests/test_cms_parity_wave.py::test_peer_*`. Remaining stock roles (meta-peer variants) niche |
| 18 | Locate responses never carry M/m manager entry types | PARTIAL | S entries only |
| 19 | cms.fsxeq external program per namespace op | MISSING (deliberate — no fork/exec per op) | node_ops planner substitutes |

---

## 3. Storage layer (XrdOss core + FRM daemons + Oss* plugins)

**PRESENT:** localroot/remoteroot via confined resolve + site_n2n (IDENTITY/RAL/CEPHFS
schemes); r/o / r/w / forcero via allow_write+read_only (invariant 3); nearline tier
flag = `stage`; openat2 RESOLVE_BENEATH (XrdOssAt analog); thread-pool AIO + backend
async queue; kXR_Qspace wire; **FRM dissolved in-process**: sd_frm nearline driver
with exec MSS adapter + dlopen lib adapter + stub simulator (`frm.stagecmd`,
`residency_cmd`, `migrate_copycmd`, `stage_dir/ttl/wait`, `async_recall`,
`control_dir`); stage engine = durable journalled queue (RECALL/FLUSH/UPLOAD/
MULTIPART) + restart replay + reconcile; historic FRM reqid wire format preserved
(`<seq>.<pid>@<host>`); owner-checked cancel; custodial pin; SHM stage waiter with
kXR_waitresp+attn cross-worker delivery (stronger than stock's poll model);
migration-out on staged_commit with per-user identity journalled; xfr concurrency/
hold/backoff knobs; fail-file semantics as journal retry state; single-flight fill
locks (8 opens → 1 recall proven); read-cache purge richer than frm_purged for the
cache tier (two-pass LRU + watermark hysteresis + demote-to-cold-tier); CSI per-block
CRC in xmeta (replaces .xrdt sidecars) + background scrub (EXTRA — OssCsi has none) +
`BRIX_SD_CAP_FSCS`; CNS emit wrappers; scan engine (verify/inspect/inventory/drift/
bench/health) + xrdstorascan; fault/return-code injection lab ≈ OssMirage; unified
metrics + latency histograms supersede OssStats.

**Gaps:**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | **Space groups**: `oss.space` multi-partition groups, alloc minfree/headroom/fuzz, `.anew` protocol, reloc between spaces | MISSING | tiers are single-location (`tier.h`) |
| 2 | `oss.cgroup` CGI space selection at create; `space.c` hardcodes `oss.cgroup=default`, `oss.quota=-1` | MISSING | `protocols/root/query/space.c:91` |
| 3 | Persistent usage ledger + quota outside pblock (pblock has full SQLite uid/gid rollup + EDQUOT; posix/S3/HTTP have statvfs only) | PARTIAL | XrdOssSpace Usage/Quota file analog |
| 4 | **Tape online-buffer purge policy** (frm_purged F1/F2): monitor logs only, never acts; MSS adapter has `purge` verb, nothing drives it; no external polprog | MISSING (explicit scope-out at FRM dissolution — revisit) | history-storage-and-caching.md §6 |
| 5 | **OssArc**: dataset→zip aggregation to tape, member-indexed recall, backup queue | MISSING | largest tape gap for small-file workloads; compose step in stage engine |
| 6 | RAM caches: oss.memfile mmap/mlock/preread; XrdRmc block cache; server-side preread policy | MISSING | natural fit as `ram:<size>` cstore driver |
| 7 | MSS namespace gateway: sd_frm has no dirlist/opendir (pure-tape namespace enumeration = ENOTSUP); no rcreate | PARTIAL | rsscmd dread analog |
| 8 | Scan engine walks raw POSIX, not the SD seam — frm_admin-audit parity broken for non-POSIX backends; `BRIX_SD_CAP_CATALOG` exists but unused by scan | PARTIAL | documented architecture gap |
| 9 | `oss.maxsize` create-size cap | MISSING | check in vfs_write/staged-commit |
| 10 | Per-subtree path attributes (nomig/mkeep/nocheck/inplace/rcreate, attribute inheritance engine) | MISSING | attrs attach to export/tier only |
| 11 | Serving stored per-4KiB page CRCs for pgRead (CSI granule is 1MiB, edge blocks verified by scrub not hot path; wire CRCs computed at edge) | PARTIAL-BY-DESIGN | divergence documented in csi_tagstore.h |
| 12 | stagemsg/StageEvents external notification file | MISSING | in-band waiter + ledger substitute |
| 13 | oss.statlib stat-info seam (GPFS etc.) | MISSING | drivers stat directly |
| 14 | Sizes-only synthetic backend (Mirage's zero-storage pattern reads) | MISSING | trivial SD driver if wanted |
| 15 | OssStats `slowop` threshold classifier + mid-op duration increments | PARTIAL | latency booked at completion |
| — | fdlimit | N/A (deprecated upstream) | |

---

## 4. Proxy + caching (XrdPss / XrdPfc / XrdPosix / XrdRmc)

Architecture map: XrdPss+XrdPosix ⇒ BriX remote SD drivers (`sd_xroot`, `sd_http`,
`sd_remote`); XrdPfc ⇒ cache decorator (`sd_cache*` + cstore) + stream-plane
`fs/cache/`. Tier grammar `cache(stage(backend))`.

**PRESENT:** origins root/http/davs/S3/pelican/local (breadth exceeds XrdPss);
ranked multi-endpoint HTTP failover with health scoring (stronger than upstream for
HTTP; root:// single-endpoint same as stock); full op forwarding on sd_xroot (open/
pread(v)/pwrite/fstat/ftruncate/fsync/stat/rename/unlink/mkdir/truncate/server_copy/
xattr×4/opendir/readdir/staged_* + cred-scoped variants + Qcksum ≈ XrdPssCks);
sd_http WebDAV mutations (MKCOL/MOVE, staged PUT/DELETE); sd_remote S3 via `path/`
markers; partial-file block caching with sparse fd + bitmap + cinfo present-bits +
COMPLETE promotion (`sd_cache_partial.c`, slice plane twin); watermark purge
HWM→LWM hysteresis + two-pass LRU + dirty protection + statvfs sampler + on-fill
safety net; cinfo v3 versioned w/ legacy read paths, flock RMW, torn-write safety,
origin validity reset, TTL/verify/write-back state (superset axes); fill-time digest
verification (`brix_cache_verify off|best-effort|require`; Qcksum / RFC-3230) +
at-rest CSI scrub (stronger than pfc.cschk cache mode); cache-admission filter
(deny-prefix→allow→size-cap w/ regex bypass, fail-closed) ≈ decisionlib compiled-in;
local stat short-circuit from cinfo (authoritative-hit doctrine); x509/token/krb5
delegation carry into fills (exceeds upstream); pfc.spaces analog (state root +
cstore meta modes); writethrough far richer (async flush engine, FRM journal, replay,
dirty reaper); hdfsmode analog (slice files); localroot/N2N. **EXTRA:** store-then-
evict passthrough, coalesced waiters + bounded retry w/ endpoint rotation, stale-if-
error, demote-on-evict, GCAS hardlink dedup, pelican federation, manager
self-registration after fill.

**Gaps:**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | **Background block prefetch** (`pfc.prefetch` in-flight max, prefetch score/disable-on-random) — no speculative origin reads anywhere; only local fadvise WILLNEED | **LANDED 2026-08-05** | Generic VFS feature through the driver `read_advise` (WILLNEED) slot: `sd_cache_prefetch.c` posts detached thread-pool jobs that fill absent successor blocks (per-handle rolling frontier, runway capped by `brix_cache_prefetch_window`, in-flight capped by `brix_cache_prefetch`, XrdPfc disable-on-random parity in the root engine). Hint engines: root:// sequential-read window + HTTP memory-backed serve loop. Counters `brix_cache_prefetch_{jobs,blocks,failures}_total`; suite `tests/test_vfs_prefetch.py` |
| 2 | ~~Age-based purge of CLEAN cold files (`purgecoldfiles`) — unconditional-age reaper covers dirty only~~ | **LANDED 2026-08-09** | `brix_cache_cold_max_age <secs>` (0 = off, the default: this DISCARDS serviceable cache, so it is only ever an explicit choice). New `BRIX_CACHE_REAP_COLD` reason on `brix_cache_dirty_reaped_total{reason="cold"}`. Age = the LATER of atime/mtime, so a noatime/relatime mount degrades to "age from fill" instead of purging a hot cache. The reaper walk now runs for EITHER horizon (it was gated on the dirty one alone). **Also fixed en route:** `reap_remove` logged every reap as a success without checking — a data file the cstore adapter failed to evict was reported reaped, lost its `.cinfo`, then looked untracked forever: a leak that logged as success. It now verifies, falls back to `unlink`, and logs an error if the file survives. |
| 3 | Per-page origin verification for partial fills (pgRead net cschk) + `uvkeep` (age-out never-verified entries) | PARTIAL | slice fills trust TLS; best-effort commits unverified forever |
| 4 | ~~`onlyifcached [minsize/minfrac]`~~ | **LANDED 2026-08-09** (minsize/minfrac not taken) | `brix_cache_only_if_cached on` (tier grammar, all protocols). In `sd_cache_open_common` a read MISS returns ENOENT → kXR_NotFound so the client fails over to another replica instead of making this node pull the object. Gated AFTER the hit test (a cached object still serves) and BEFORE the admission filter and the nearline/fill paths — otherwise an admission-declined path would still reach the source, the exact bypass the mode exists to prevent. Writes always pass through. The `minsize`/`minfrac` partial-hit thresholds are NOT implemented (a partial hit counts as a miss). |
| 5 | Serve-while-filling whole-file mode (background prefetcher, read queue-jumping, stop-on-close) — BriX whole-file fill is foreground, first reader waits | PARTIAL | slice mode covers latency case |
| 6 | chmod + statfs/Stats forwarding on sd_xroot (no .setattr→kXR_chmod slot) | PARTIAL | XrdPss forwards Chmod |
| 7 | File-usage (cached-bytes-owned) watermarks distinct from FS occupancy (`diskusage files`) | MISSING | matters on shared filesystems; cstore visitor provides input |
| 8 | Per-directory stats/quota tree (dirstats/DirState/ResourceMonitor/purge-pin) | MISSING | global counters only |
| 9 | Direct cache access (`pss.dca` redirect-to-local-path) | MISSING | largely obviated by sendfile; manager re-registration is the cousin |
| 10 | Forwarding-proxy mode (client-named origin URL + protocol allowlist) | MISSING | security-sensitive; reuse TPC egress-verdict core |
| 11 | Admin evict/fevict verb | MISSING | programmatic evict exists; no operator command |
| 12 | RAM budget/writequeue for fills; RAM-only cache tier (XrdRmc) | MISSING / N-A-leaning | OS page cache substitutes for serving |
| 13 | Per-open CGI blocksize/prefetch override (`pfc.urlcgi`) | MISSING (likely deliberate under opaque_strict) | |
| 14 | pss.permit host ACL, pss.persona mapped identity (BriX forwards REAL identity instead — arguably better), pss.reproxy, root:// origin connection pool (per-fill bootstrap today) | MISSING/low | pool matters only if origin-open latency shows up |
| 15 | cinfo per-access history ring (`acchistorysize`) + cinfo self-CRC | PARTIAL | aggregates only; bit-flip in well-formed cinfo undetected |

---

## 5. Security (XrdSec* / XrdAcc / SciTokens / Macaroons / VOMS / TLS)

**PRESENT:** full sigver verify path (stock secver-0, seqno replay, constant-time,
pedantic payload rule); 5 security levels; GSI byte-faithful (certreq/cert rounds,
XrdSutBuffer framing, DH+session cipher, PoP, signed-DH v10400 both directions,
foreign-CA issuer-hash fix + regression guard, CRL modes+reload+*.r0, proxy
delegation kXGS_pxyreq/sigpxy RFC-3820-faithful, gridmap file, VOMS AC extraction
via dlopen libvomsapi hardened, per-user proxy conventions, xrdgsiproxy/xrdgsitest);
krb5 (principal/keytab, ipchk, multi-leg GSS, fwd-TGT capture SM + FILE-ccache carry
+ outbound leg vs live KDC); sss (Blowfish-CFB64+CRC32, keytab kernel, mutual LGID
challenge, xrdsssadmin stock-interop); pwd core handshake byte-compatible (DH
bootstrap, PBKDF2 DB); unix (loopback-gated, stricter); host (rDNS+mandatory
allowlist, fail-closed, stricter); ztn both framings + WLCG client discovery; JWT
in-process validation (RS256/ES256, alg:none rejected, JWKS hot-reload, L1/L2
caches); SciTokens scitokens.cfg verbatim grammar + scope→path capability mapping on
all 3 protocols; macaroons mint (dCache-style + OAuth2 + discovery) + verify + secret
rotation (EXTRA) + third-party discharges (EXTRA); xrdacc authdb faithful port
(record types `= x s g h n o r t u`, 9-bit privs + negatives, numerically identical
composite ops, @= templates, netgroups, rDNS rules w/ circuit breakers, hot-reload,
audit, full acc.* directive set, applied to all 3 protocols); crypto = OpenSSL 3
direct with byte-exact ported behaviors; TLS in-protocol upgrade + kTLS (EXTRA) +
OCSP/stapling (EXTRA) + Globus signing_policy (EXTRA). **EXTRA:** S3 SigV4+STS,
impersonation broker (SCM_RIGHTS), negcache backoff, TPC egress guard, DH keypool,
handshake inflight caps.

**Gaps:**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | ~~**`sec.protbind`** per-host templates (none/only) + arbitrary ordered multi-protocol sectoken (one scheme/listener; only ztn+gsi composes via `both`)~~ **LANDED 2026-08-05**: generic engine in `src/auth/protbind/` (XrdOucNList-compatible templates, `none`/`only`/default modes, first-match-wins, per-connection reverse-DNS cache) driving `kXR_protocol` advertisement, the ordered `&P=` sectoken and the `kXR_auth` credtype gate — plus the HTTP/WebDAV frontend through the *same* parser and resolver. Naming a scheme in a rule now pulls its keys/certs into startup validation. | DONE | `auth/protbind/{match,policy,config,peer}.c`, `session/{protocol,login}.c`, `webdav/access_auth.c`; `tests/c/protbind_test.c`, `tests/test_protbind_parse.py` |
| 2 | **Signing-level table conformance**: BriX compatible=nothing (stock: chmod/fattr/mv/rm/trunc…); standard signs writes (stock: intense); intense signs ~all (stock exempts reads until pedantic). Plus no `relaxed`/`force`/local-remote split; no kXR_signLikely heuristics. **The silent-bypass half is FIXED 2026-08-09**: `brix_signing_enforce_level` used to return "continue" before any check whenever `signing_active==0`, so on an sss/ztn/krb5/anonymous session (only GSI arms a key) `brix_security_level` enforced NOTHING and logged nothing. It now logs one WARN per session naming the level and what happened, and `brix_signing_required on` REFUSES the request (kXR_NotAuthorized) instead of accepting it unsigned. Default off — turning it on rejects every stock non-GSI client, which is a deployment decision. Handshake opcodes stay exempt at every level. | DIVERGENT/PARTIAL (bypass closed) | `gsi_core.c`, `handshake/sigver.c`. STILL OPEN: actually KEYING sss/krb5 sessions (both have key material and stock signs sss) — that is a wire change requiring matching client+server derivation, so it is deliberately not bundled here. |
| 3 | ~~**Per-capability TLS** (`xrootd.tls login/session/data/tpc` + `-cap` exceptions + kXR_tls* advertisement) — coarse `brix_min_sec_level` floor instead; ztn accepted over cleartext unless opted in (stock refuses)~~ **LANDED 2026-08-05**: generic VFS `brix_tls_require` mask (stream pre-dispatch + native-TPC choke + WebDAV + S3), kXR_tlsLogin/Sess/Data/TPC advertised at `kXR_protocol`, ztn now refused over cleartext by default (`brix_ztn_cleartext` lab opt-in) | DONE | `fs/vfs/vfs_secgate.c`, `handshake/policy.c`, `tests/test_tls_require.py` |
| 4 | VOMS: FQAN-pattern→user mapfile (XrdVomsMapfile); vomsfun certfmt/grpopt/vos/grps filters; global "AC required" independent of path rules | MISSING/PARTIAL | identity mapping by FQAN absent; authz by VO present |
| 5 | SciTokens: rule-based name_mapfile (sub/path/group predicates — BriX flat JSON only); upstream-compatible `onmissing passthrough/allow/deny` for tokenless requests | PARTIAL | `subject_map.c`, `issuer_registry.h:43` |
| 6 | sss v2 entity breadth: vorg/role/caps/**endorsements**/attr pairs/proxied creds not parsed; XrdSecsssID per-connection registry (multiplexing proxies); --getcreds | PARTIAL/MISSING | `sss_internal.h:15-24` |
| 7 | pwd extras: auto-registration `-a:`, syspwd, per-user $HOME files, cryptfile, client-verification `-vc`, maxfail, cred export, **xrdpwdadmin tool** | MISSING | low demand |
| 8 | GSI options: `-gmapfun` DN-regex mapping (exact-DN file only), gmapopt mode matrix, `-exppxy` file-export templating, `-authzpxy`, ca `noverify/verifyss`, `-crlext`, md list directive, trustdns/showdn/moninfo | MISSING/PARTIAL | mostly relaxations BriX chose not to have |
| 9 | ztn `-expiry ignore/optional` (BriX = required only), `-maxsz` knob | PARTIAL | stricter default |
| 10 | xrd.tlsca residuals: crlcheck last-scope, verdepth for stream listener, verification-log toggle; xrootd.tlsreuse; xrd.tlsciphers for stream listener | PARTIAL/MISSING | nginx covers HTTP side |
| 11 | authdb residual grammar: `v`/`l` selectors in compound ids, `x` privilege | MISSING | decision-identical otherwise |

---

## 6. HTTP stack + TPC (XrdHttp / XrdHttpTpc / XrdHttpCors / ofs.tpc / SRR / Dig)

**PRESENT:** verb superset (15 incl. LOCK/UNLOCK/PROPPATCH/ACL/SEARCH — stock has
none of those); PROPFIND depth 0/1/**infinity** (stock fakes infinity); single+
multipart ranges w/ TLS/sendfile invariant; chunked both directions; Want-Digest →
Digest on HEAD (RFC 3230 normalization + `?xrd.want.cksum=`) + streaming GET adler32
trailer (EXTRA) + PUT ingest digest verification (EXTRA — stock has none); CORS
richer than XrdHttpCors (preflight, credentials, TPC-aware header list); gridmap;
secxtractor function native (proxy chain verify + VOMS); dual-protocol same-port via
first-bytes handoff (`brix_http_handoff`, inverted vs stock but same net effect);
macaroon endpoints (§5); HTTP-TPC: COPY pull+push, **multi-stream pull** via
curl_multi ranges + per-stream SciTag pmark, perf markers exactly per WLCG contract
(chunked, per-stripe, terminal success/failure), TransferHeader* forwarding,
Credential delegation broader than stock (OAuth2 token-exchange + macaroon + GridSite
+ per-user proxy — stock rejects non-none Credential!), Overwrite, allow local/
private, SSRF Layer-2 egress allowlist (EXTRA), low-speed abort, TLS material knobs;
native TPC: both roles, SHM rendezvous key registry + live registry, kXR_wait/
waitresp open resolution, checksum verify fail-closed + unlink, always-on autorm
(stricter), delegation-rich outbound (GSI/bearer/OIDC), mesh-driven TPC redirect,
require_source_size (EXTRA); SRR native JSON endpoint (upstream has none in-tree);
Dig re-shaped to `/.well-known/dig/` with RESOLVE_BENEATH + principal allow-file.

**Gaps:**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | ~~**HTTP redirect-to-dataserver missing**: the dormant `xrdhttp_send_redirect`/Location+X-Xrootd-Redir-* scaffolding was **removed 2026-08-05** (phase-95 W1); no `http.secretkey` signed-CGI handoff~~ | **LANDED 2026-08-09** | `brix_webdav_redirect_dataserver on` 307-redirects GET/HEAD/PUT to the CMS-registry-selected data server (`webdav/redirect.c`, mesh selection via `brix_srv_select`); `brix_http_secretkey` signs the authenticated identity into the redirect CGI (`brixrdr.exp/usr/vo/mac`, HMAC-SHA256 binding method+path+expiry) and the data-server side verifies it constant-time + expiry-bounded, adopting the identity fail-closed. BriX-dialect CGI (not byte-compatible with stock XrdHttp's hash — upstream tree unavailable to verify its exact format); same trust model. `tests/test_webdav_redirect_ds.py` (7 cases: 307, valid GET served, loop-guard, tamper/expiry/foreign-key/path-mismatch 403) |
| 2 | **HTTP-TPC checksum verification**: no Repr-Digest HEAD cross-check, no RequireChecksumVerification (native TPC has verify; WebDAV COPY trusts transfer) | MISSING | |
| 3 | ~~**TPC push skips Layer-2 egress allowlist** (pull enforces)~~ | **ALREADY FIXED 2026-08-04** (this row was stale) | The push branch of `ngx_http_brix_webdav_tpc_handle_copy` runs `webdav_tpc_source_guard()` on the `Destination` authority before `webdav_tpc_handle_push()` — same verdict core, same 403, same `signal=tpc_egress` line as a pull (`webdav/tpc.c:347-363`). Covered by `tests/test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse` (4 cases). See testsuite-combinatorial-coverage-audit-2026-08-04.md §2.2. |
| 4 | Want-Digest q-value/multi-algorithm negotiation (first token only) | PARTIAL | `xrdhttp_normalize_rfc3230_algo` |
| 5 | `http.header2cgi` arbitrary header→CGI bridge | MISSING | |
| 6 | HTML directory listing on GET + listingdeny/listingredir | MISSING | PROPFIND-only enumeration |
| 7 | ofs.tpc identity matrix: `allow dn/group/host/vo`, `require {all|client|dest} <auth>`, `restrict <path>`, `oids` | MISSING | host-plane + global confinement substitute |
| 8 | Native TPC multi-stream (`ofs.tpc streams`) — single-stream 1MiB loop; push multi-stream also N/A | MISSING | HTTP pull has it |
| 9 | `xfr <n>` explicit concurrency cap (implicit via registry slots + pool width); split client-TTL vs max TTL | PARTIAL | |
| 10 | Perf-marker `RemoteConnections:` line | PARTIAL | minor |
| 11 | tpc.fixed_route; http.maxdelay; selfhttps2http | MISSING | low value |
| 12 | Dig over root:// plane (`/=/`) | PARTIAL | HTTP-only by design |
| 13 | One brix-HTTP protocol per port (webdav|s3|cvmfs exclusive) vs sharing | DIVERGENT | root+http handoff pairing exists |

---

## 7. Client stack (XrdCl / xrdcp / xrdfs / preload / FUSE / XrdEc / apps)

The repo's `docs/10-reference/xrootd-feature-matrix.md` "XrdCl: No" row is STALE —
`client/` is a full native client (sync + epoll/io_uring async cores, GSI/sss/pwd/
krb5/token auth incl. client-side GSI delegation round, pgread/pgwrite w/ pgRetry on
write, readv/writev, ZIP, TPC orchestration, capture/replay, resilient reopen-resume,
`~/.xrdrc` endpoint aliases). Machine-checked xrdfs parity gate exists
(`tests/test_clientconf_surface.py` live-parses stock XrdClFS.cc).

**Gaps (ranked):**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | ~~**Metalink** end-to-end~~ | **LANDED 2026-08-09** (phase-100) | v4+v3 parser + virtual-redirector failover + digest inheritance, all source transports; --tls-metalink / --zip-mtln-cksum deliberately not taken (phase-100 §3) |
| 2 | ~~**Extreme copy** (--sources, XCp block-stealing multi-replica)~~ | **LANDED 2026-08-09** (phase-100) | `--sources N` engine: metalink mirrors → locate → duplication; block stealing + dead-replica rescue; --dynamic-src not taken (needs known size) |
| 3 | **Sub-stream data fan-out**: kXR_bind done, pathid never stamped (`net/streams.c:9-14`) — `--streams` cosmetic; GSI-signed sessions also rejected by aio attach (no pipelining when signed) | PARTIAL | pairs with server §1 gap 1 |
| 4 | ~~**tried=/triedrc= never emitted** by BriX clients (server parses them!)~~ | **LANDED 2026-08-09** (dead-target failover; DS-error retry still open) | `frame_roundtrip.c`: when a redirect target is unreachable and the client falls back to the home manager, the replayed request carries `tried=<hostport>&triedrc=<reason>` with the stock reason tokens (enoent/ioerr/fserr/srverr). Emitted only for the opcodes BriX's own manager parses `tried=` for — open/stat/query (`open_manager.c`, `stat_manager.c`, `checksum_qcksum_path.c`) — so emission and consumption cannot drift, and never on a first attempt. NOT taken: retrying at the manager when a data server returns an ERROR (that is a behaviour change, not an emission gap). |
| 5 | ~~**`--tpc delegate` hardcodes `tpc.dlgon=0`** — silently degrades to `first`~~ | **LANDED 2026-08-09** | `tpc_build_dst_opaque` emits `tpc.dlgon=1` for `XRDC_TPC_DELEGATE`, 0 otherwise. The wire flag alone was not enough: the client also REFUSED the destination's kXGS_pxyreq round unless `$XRDC_GSI_DELEGATE` was set, and advertised no delegation capability, so a stock destination would never ask. `--tpc delegate` now sets `brix_opts.gsi_delegate`, which one predicate (`gsi_delegation_enabled`) drives for both the kOptsSigReq advertisement and the sigpxy round — advertise and honour can no longer disagree. |
| 6 | **`--continue` byte-offset resume** — partials unlinked on failure; journal (`--journal/--resume`, EXTRA) is whole-file only | MISSING | `copy_local.c` |
| 7 | **fork-safety** — no pthread_atfork; forked child inherits aio fds → hang/SID collisions | MISSING (unsafe) | HEP frameworks fork |
| 8 | **Preload**: read-only shim — no write path, no readdir family (documented punt), no stdio (fopen…), no statfs/chdir/xattr/__xstat aliases; single conn + global mutex; BRIX_VMP single mapping vs multi XROOTD_VMP; `fill_stat` under-fills (latent bug, bypasses `posix_map.c` helper) | PARTIAL (deliberately narrow) | |
| 9 | **xrootdfs**: no multi-data-server fan-out/dirent merge/nworkers (the defining XrdFfs feature), no CNS journal, no per-request sss uid/gid identity (all users collapse to mounting user), no ofsfwd, no SIGUSR1 refresh, no special xattrs; mknod absent; usage text stale (utimens/chown/symlink ARE implemented) | PARTIAL | extras: WebDAV backend, resume, readahead/writeback, stable inodes |
| 10 | **Zero `XRD_*` env compatibility** (~40 stock keys silently ignored; own XRDC_* namespace) — drop-in hazard | MISSING | envalias.c covers only 2 legacy names |
| 11 | Redirect collapse / VirtualRedirector registry client-side (also the metalink hook); async engine doesn't follow redirects itself | MISSING/PARTIAL | |
| 12 | xrdfs residuals: multi-path stat/rm/cat act on LAST path only (silent); `ls -u/-D/-Z/-C`; `stat -q` flags; locate flags all missing (options=0 hardcoded) + deep-locate; query 5/9 codes missing; prepare -p/-a; spaceinfo not drop-in (aliased df); cache evict/fevict verb; xattr grammar incompatible; REPL thin | PARTIAL | 37 verbs + 19 EXTRAS otherwise |
| 13 | xrdcp residuals: --coerce, -p/--path, --xrate(+threshold), --xattr, --rm-bad-cksum, --retry-policy, sha-family cksums, cksum on TPC/web paths; ZIP surface divergent (CGI ?xrdcl.unzip= vs --zip flag; BriX --zip means store-into-archive); several stock spellings rejected (--parallel/--force/--recursive/--nopbar) | PARTIAL | extras: --sync/--delete/--exclude/--jobs/journal |  <!-- client-flags-allow: the row IS the list of stock flags BriX does not implement -->
| 14 | pgread client per-page re-request on CRC mismatch (hard error today; write side has pgRetry) | PARTIAL | |
| 15 | readv single fhandle per request (stock: per-segment) | PARTIAL | |
| 16 | Declarative ops DSL (XrdClOperations) | MISSING | |
| 17 | file:// transparent local handler (`brix_connect` rejects non-root://; VFS facade exists but callers must branch) | PARTIAL | |
| 18 | kXR_attn actions beyond asynresp (asyncrd/wt/go/di/ab/ms) ignored | PARTIAL | |
| 19 | Connection multiplexing: no global URL→channel registry/PostMaster (explicit per-callsite pools); no StreamErrorWindow cross-op endpoint memory | PARTIAL | |
| 20 | Apps: xrdpwdadmin MISSING; cconfig MISSING; xrdacctest-as-CLI MISSING (server engine exists; diag_authsuite is different); xrdcks local xattr tool MISSING; xrdreplay/RecordPlugin ≈ wire-level capture/replay only (no op-level CSV, timing, verify modes); xrdmapc/xrdqstats/xrdprep PARTIAL (flag subsets); wait41 semantics divergent (name collision); crc32c flags subset | MISSING/PARTIAL | EXTRAS: xrdckverify, xrdcinfo, xrdcksum manifests, xrdstorascan, fault-proxy, xrddiag doctor (~25 TUs), brixMount family |

**XrdEc (erasure coding): MISSING, 0%.** Zero code repo-wide; only `kXR_ecRedir`
defined-never-set. Own docs record it as a hard blocker. Everything absent: ObjCfg,
StrmWriter, Reader reconstruction, ClEcHandler, isa-l dep, ecRedir semantics.

---

## 8. Frameworks: SSI / BWM / Throttle

**SSI — PARTIAL (~70% server, byte-exact; 0% client-lib).** PRESENT: RRInfo codec +
Attn prefix (golden vectors), session multiplex (8 reqIds, 9th→kXR_Overloaded),
cancel, data/stream/error kinds, metadata, async attn push w/ conn-generation UAF
guard (stronger than stock), proven against real libXrdSsi C++ client. EXTRA:
svc_cta CTA tape frontend. MISSING: isFile/isHandle kinds; rUser/rInfo/hAvoid
resource CGI (discarded); affinity/XrdSsiScale; **XrdSsiShMap entirely**; SsiCms
cluster integration; SsiDir; client-side SSI library. Alerts dropped during sync
submit phase (`ssi_dispatch.c:98-106`).

**XrdBwm — PARTIAL (~20%).** `net/ratelimit/reservation.c` wired into read-open only
(`is_write` early-return exempts writes; TPC unreserved). Collapsed semantics:
binary grant/refuse (no queued state/Dispatch wake), release by bytes not handle, no
Incoming/Outgoing flows, no SchedParms, no visa, no policy engine, no logger;
`brix_resv_status` has no product caller (it is the unit test's observation point);
per-worker static (budget × workers — SHM upgrade flagged); "bandwidth" budget is actually a concurrent-bytes admission cap.

**XrdThrottle — PARTIAL, split picture.** Missing upstream's triple: throttle.data
(rate pacing of in-flight streams), throttle.iops, loadshed, max_wait_time, fairness
algorithm, delay-not-reject opens. `throttle_compat.c`: max_open_files PRESENT
(per-DN, e2e tested) and is now the ONLY engine in that file — phase-95 deleted
max_active_connections (parsed-but-dead directive), the IO-load concurrency metric
and the userconfig per-user INI, all of which had zero call sites. What runs
instead (EXTRA, identity-richer but semantically different): SHM-shared
`brix_rate_limit_zone/rule` (req/s), `brix_bandwidth_limit` (bytes/s leaky bucket on
every root:// data path), `brix_concurrency_limit`, keyed by VO/issuer/IP/DN-hash/
volume/JWT-subject, on root://+WebDAV, kXR_wait replies, metrics+dashboard.
Cache-fill paths are un-throttled. `source-verified-xrootd-comparison.md:265`
"Parity" claim is optimistic.

---

## 9. Cross-cutting punch lists

### 9.1 Ranked master gap list (feature bodies, biggest first)
1. Erasure coding (XrdEc) — greenfield.
2. ~~Metalink (client parse + VirtualRedirector semantics; server N/A)~~
   **LANDED 2026-08-09** (phase-100).
3. ~~Multi-stream data path BOTH sides~~ **LANDED 2026-08-04** (phase-94, as the
   bound-connection read/write data path + client fan-out; see that doc).
4. ~~Extreme copy (XCp) client engine~~ **LANDED 2026-08-09** (phase-100,
   `--sources N` block-stealing engine).
5. ~~CMS multi-manager failover (§2.1)~~ **LANDED 2026-08-05**; ~~SUPCount floor
   (§2.2)~~, ~~stage-aware selection (§2.5)~~, ~~cms.sched weights (§2.3)~~,
   ~~fxhold/emptylife (§2.6)~~, ~~kXR_refresh bypass (§2.7)~~, ~~cms.dfs
   (§2.8)~~, ~~ManTree login offload (§2.9)~~, ~~cms.perf pgm (§2.11)~~,
   ~~cms.altds (§2.12)~~, ~~blacklist patterns/whitelist/redirect (§2.13)~~,
   ~~peer/proxy roles (§2.17)~~ all **LANDED 2026-08-09**
   (`tests/test_cms_parity_wave.py`). Remaining §2 open: cms.space hysteresis
   (§2.4), full ManTree tree negotiation (§2.9), meta-manager ClustID/gshr
   (§2.10), request coalescing (§2.15), M/m locate entry types (§2.18).
6. Cache prefetch (§4.1) + cold-file age purge (§4.2) + onlyifcached (§4.4).
7. Space groups/cgroup/quota generalization (§3.1–3).
8. ~~sec.protbind + multi-protocol sectoken (§5.1)~~ **LANDED 2026-08-05**
   (`src/auth/protbind/`, both frontends); signing-table conformance (§5.2) still open.
9. ~~Per-capability TLS gating + kXR_tls* advertisement (§5.3)~~ **LANDED
   2026-08-05** (`brix_tls_require` + `brix_ztn_cleartext`).
10. OssArc zip aggregation (§3.5); tape-buffer purge engine (§3.4).
11. ~~HTTP redirect-to-dataserver wiring (§6.1)~~ **LANDED 2026-08-09**
    (`webdav/redirect.c` + `brix_http_secretkey` signed handoff,
    `tests/test_webdav_redirect_ds.py`); ~~HTTP-TPC checksum verify (§6.2)~~
    landed earlier (`webdav/tpc_verify.c`).
12. Preload write/readdir/stdio (§7.8); xrootdfs fan-out + sss identity (§7.9);
    fork-safety (§7.7); XRD_* env compat (§7.10); tried= emission (§7.4).
13. RAM cache tier (XrdRmc/memfile) (§3.6/§4.12).
14. SSI client lib + ShMap (§8); BWM queueing/flows; throttle.data/iops pacing.
15. Long tail: VOMS mapfile, SciTokens rule mapfile, sss v2 entity/ID registry,
    pwd admin/auto-reg, header2cgi, HTML listings, ofs.tpc identity matrix,
    fsoverload, QStats XML, Qconfig keys, admin socket. (fxhold TTL knobs,
    cms.dfs, cms.perf pgm, altds, blacklist patterns/whitelist/redirect,
    error constants all landed 2026-08-09.)

### 9.2 Verified bugs / dead code found during this audit
- ~~TPC push skips Layer-2 egress allowlist (pull enforces)~~ **ALREADY FIXED 2026-08-04** — this row was stale when written; the push branch guards the `Destination` authority (`webdav/tpc.c:347-363`) and `test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse` covers it. See testsuite-combinatorial-coverage-audit-2026-08-04.md §2.2.
- ~~`xrdhttp_send_redirect` implemented, zero call sites (dormant HTTP redirects).~~ **REMOVED 2026-08-05** (phase-95 W1), then **RE-IMPLEMENTED FROM A REAL CALL SITE 2026-08-09** (§6.1) — `webdav/redirect.c` selects the data server from the CMS registry (`brix_srv_select`) and signs the identity into the redirect CGI (`brix_http_secretkey`); no dormant scaffolding, wired into `webdav/dispatch.c` + the access-phase auth gate.
- ~~`--tpc delegate` hardcodes `tpc.dlgon=0` (silent downgrade)~~ **FIXED 2026-08-09** — dlgon now tracks the mode, and the client arms its own delegation (advertise + honour behind one predicate) so the mode works end-to-end rather than only on the wire.
- xrdfs multi-path stat/rm/cat silently act on last path only.
- ~~Throttle: `max_active_connections` parsed-never-enforced; IO-load + userconfig engines have zero call sites~~ **REMOVED 2026-08-05** (phase-95 W2, deletion variant) — the `brix_throttle_max_active_connections` directive, the `brix_throttle_userconfig_*` INI matcher, the `brix_throttle_charge_io`/`ioload_over` load metric and the `io_time_us`/`io_window` SHM node fields are all gone. `max_open_files` is the one throttle engine with an admission point and it stays. `brix_resv_status` KEPT deliberately: it has no product caller but it is the observation point for `tests/c/test_reservation.c`, which covers the live `brix_resv_schedule`/`done` engine — deleting it would trade dead code for lost coverage.
- Preload `fill_stat()` duplicates and under-fills vs `posix_map.c:17` helper (no st_ino/blksize/blocks).
- sss/ztn/krb5 sessions never signing-keyed (`signing_active=0`) — request-tamper protection absent off-GSI. **The SILENT half is fixed 2026-08-09** (`handshake/sigver.c`): the enforcement no longer short-circuits before its own check — it logs one WARN per session and, with `brix_signing_required on`, refuses. Actually keying sss/krb5 (both have key material; stock signs sss) remains open and is a wire change needing matched client+server derivation.
- **NEW 2026-08-09** — `cache_reap.c::reap_remove` logged every reap as a success without verifying it: a data file the cstore adapter failed to evict was counted+logged as reaped, then lost its `.cinfo` sidecar and looked untracked on every later pass, so it was never revisited. A leak that reported as success. Now verifies, falls back to `unlink`, and logs an error if the file survives.
- `xrootdfs_usage.c:47-48` claims utimens/chown/symlink unsupported — they are implemented.

### 9.3 Stale repo docs to fix
- `docs/10-reference/xrootd-feature-matrix.md` — "XrdCl client library: No" row stale.
- `docs/10-reference/comparison/.../source-verified-xrootd-comparison.md:265` — throttle "Parity/nginx+" optimistic vs source.

### 9.4 Deliberate divergences to leave alone (documented, not gaps)
- CSI 1MiB granule in xmeta vs 4KiB .xrdt sidecars (single-record rule; scrub compensates).
- No sidecar file zoo (.anew/.fail/.lock/…) — journal + xmeta.
- In-process CMS/FRM/TPC (no daemons, no admin unix socket by architecture).
- Always-verify GSI CA (no noverify/verifyss), ztn exp required, host fail-closed,
  autorm always-on, https required for TPC — BriX chose stricter defaults.
- nginx-native TLS/static/logging/config surface replacing xrd.* equivalents.

---

*Generated from 7 subsystem audits, 2026-08-04. Each subsystem section's file/line
citations were produced by direct source inspection of both trees on this date.*
