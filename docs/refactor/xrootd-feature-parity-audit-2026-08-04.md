# XRootD → BriX full feature-parity audit — 2026-08-04

Source of truth: seven parallel source-level audits of `/tmp/xrootd-git-src` (upstream
XRootD, all of `src/`) vs this repo, one per subsystem. Every status line below was
grep/read-verified in BOTH trees (the repo's own older comparison docs were NOT trusted —
several stale rows in them are corrected here, see §9.3).

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
5. ~~**Background prefetch in the cache** (`pfc.prefetch`)~~ — **LANDED
   2026-08-05** (§4.1: `sd_cache_prefetch.c`, `brix_cache_prefetch` /
   `_window`, `tests/test_vfs_prefetch.py`); still open — serve-while-filling
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

**2026-08-09 reconciliation pass** (status verification against the tree, no
new feature work): §6.2 HTTP-TPC checksum verification was marked MISSING but
had in fact **landed 2026-08-05** (`webdav/tpc_verify.c`, commit `6cd30f3a` —
§9.1.11 already said so; the §6 table row is now corrected); the §0.5/§9.1.6
cache rows are reconciled with §4 (prefetch landed 08-05, cold-age purge +
onlyifcached landed 08-09 — remaining cache gaps are §4.3/§4.5/§4.12); §1.8
now records the kXR_refresh locate leg as landed via §2.7; the throttle row in
`source-verified-xrootd-comparison.md` has been corrected (§9.3), and the
feature-matrix "XrdCl: No" row was corrected later the same day (parity-fix
wave, §9.3). Commits after the 08-09 waves
(CCN-15 decomposition `1085ba7e`, test file-size splits `69890d5c` — note
`test_cms_parity_wave.py` now pairs with `_test_cms_parity_wave_helpers.py` —
build/site fixes) contain no parity-status changes.

**2026-08-09 working-tree additions** (implemented with tests, in flight to
commit): (a) **extreme-copy join gate** — block claiming now starts only once
every source's open attempt has RESOLVED (succeeded or failed), capped by a
1 s grace (`XRDC_XCP_JOIN_GRACE_MS`, `client/lib/xfer/copy_xcp.c`). Without
it the first source to finish its open could drain the whole block table on a
fast link before a sibling's handshake completed — `--sources N` silently
degrading to one source. A dead mirror lifts the gate as fast as a live one;
a black-holed mirror delays start by at most the grace. Per-worker failure
lines on the debug channel make a 0-block source attributable. Regression
locks: slow-open-mirror + tarpit-mirror cases in `tests/test_extreme_copy.py`;
phase-100 doc §2.3 updated. (b) **phase-101 W1 — SciTags pmark on S3 fixed**
(see §9.2): the `brix_pmark*` family is now registered once on the shared HTTP
common module instead of being hand-copied into the webdav and s3 tables
(where first-module-wins had made S3's copy dead code); site-wide `brix_pmark
on` at server{}/http{} scope now works. `src/core/config/http_common.c`,
`tests/test_pmark_s3.py`. The wider config-surface unification this came from
is planned in `phase-101-config-surface-unification.md` (W2–W9 still open).
(c) **parity-fix wave** — small audit items implemented from this doc's own
lists, each with a success + error + security-neg test trio: §1.7 dirlist
`kXR_online` filter (`tests/test_dirlist_online.py`); §9.2 xrdfs multi-path
stat/rm/cat (`tests/test_xrdfs_multipath.py`); §9.2 preload `fill_stat`/statx
under-fill (three new tests in `tests/test_xrootdfs.py`); §9.2 xrootdfs usage
text; §9.3 feature-matrix XrdCl row. Collateral test-infra fixes: the shared
lifecycle port ladder grew two slots (532→534, every band below shifted — the
documented intentional-compatibility event), and
`test_xrdfs_report_err_sweep.py::test_two_path_formats_still_emit_hints` was
already red at HEAD (the ln sites moved to `xrdfs_attr.c` in a file split; the
sweep now follows the site, not the historic file).
(d) **§1.14 Qconfig residual + §7.13 stock spellings** — `window` now answers
the session's live SO_RCVBUF as a bare integer (emitters gained the connection
parameter); the other named keys (sysid/wan_port/wan_window/sitename/cid) were
verified LIVE against the fleet's stock 5.6.9 reference server to ECHO under a
default config — BriX's echo fallback is therefore already byte-faithful, and
no BriX directive can set them, so echo is the permanent answer
(`tests/test_query_extended.py::TestQconfigStockKeyParity`). brix-xrdcp now
accepts the stock long spellings `--force`/`--recursive`/`--nopbar`/`--silent`
as aliases (`tests/test_xrdcp_transport_opts.py::TestStockLongSpellings`,
incl. a fleet-backed --force field-level proof and truncation/value
security-negs). (e) **client PIC dep-tracking build defect (NEW §9.2)** — the
client Makefile never `-include`d the `.pic.d` dependency files, so a header
change rebuilt only the TUs whose `.c` changed and `libbrix.so`/
`libbrixposix_preload.so` linked objects compiled against DIFFERENT struct
layouts; the stale preload shim segfaulted in `brix_conn.diag` during login
(reproduced, then fixed by adding the PIC set to `ALL_OBJS`; a `touch
lib/brix.h` probe now rebuilds all dependent PIC objects).
(f) **parity-fix wave 2** — §1.11 chkpoint `brix_chkpnt_maxsz` knob
(`tests/test_chkpnt_maxsz.py`, directives.md entry, registry-guard clean) and
§6.4 Want-Digest RFC 3230 q-value / multi-algorithm negotiation
(`xrdhttp_select_rfc3230_algo`; 3 new cases in
`tests/test_xrdhttp_wait_retry_digest_range.py`, incl. the q=0 "client
refused every algorithm ⇒ compute nothing" security-neg). The shared
lifecycle ladder grew one more slot (534→535, bands below shifted — same
intentional-compatibility event as before).
(g) **parity-fix wave 3** — §1.10 `brix_max_delay` (ofs.maxdelay analog,
default 60s, clamps every kXR_wait at the `brix_send_wait` choke point;
`tests/test_max_delay.py`); §7.12 xrdfs `stat -q` (stock '&'=all/'|'=any
semantics + 0/55/50 exit codes pinned live against stock 5.6.9) and
`locate [-n] [-r] [-d] [-m|-h] [-i] [-p]` incl. deep-locate over the shared
walk and the new `brix_locate_opts` lib call
(`tests/test_xrdfs_locate_statq.py`); `kXR_prefname` added to
protocol/flags.h. fsoverload's stall/redirect overload policy and the
remaining xrdfs residuals stay open (§1.10/§7.12 rows).
(h) **parity-fix wave 4** — §6.10 perf-marker `RemoteConnections:` line
(connected endpoint per stripe, `tests/test_tpc_marker_remoteconn.py`) and
§7.12 xrdfs prepare `-p`/`-a` with the `-c`≠cancel stock-semantics repair
(wire-verified via `--capture`, `tests/test_xrdfs_prepare_flags.py`). Two
bugs found en route (§9.2): the marker tier was dark for location{}-scoped
exports (bare `thread_pool` pointer check → new shared
`brix_http_thread_pool()` lazy resolver), and `prepare -c` silently ABORTED
a stage where stock co-locates. Ladder 535→537 for the two new subjects.
(i) **§1.15 resolved + §7.14 client pgread CRC recovery** — query-by-fhandle
turned out PRESENT as a superset (stock 5.6.9, probed live via a private
stock instance, never serves a pure-fhandle Qcksum/Qxattr — ArgMissing —
while BriX genuinely computes by handle; error CODES already matched;
`tests/test_query_by_fhandle.py` pins both halves). The client paged read
now RECOVERS a corrupt page instead of aborting: collect-decode, then a
bounded per-page re-request carrying the §1.2 kXR_pgRetry args (2 tries per
page, ≤16 pages, poisoned-stream refusal beyond; fail-closed when a page
stays bad). Deterministic MITM bit-flip suite
`tests/test_pgread_client_retry.py`, fail-verified with retries disabled.
(j) **parity-fix wave 5 — operator cache evict** (§4.11 + a §7.12 residual):
stock `xrdfs cache {evict|fevict}` lands as kXR_set "cache <verb> <path>"
(wire pinned live against 5.6.9); the set handler now runs it through the
delete-grade gate (allow_write enforced IN-handler — kXR_set bypasses the
write-plane dispatcher gate — then BRIX_AUTH_DELETE + token scope on the
confined path) and `brix_sd_cache_evict`; BriX xrdfs grew the matching
`cache` verb over the new `brix_set_cmd`. `tests/test_cache_evict_cmd.py`
incl. a stock-client drop-in proof. Ladder 537→538 (lc-cache-evict).
(k) **parity-fix wave 6** — §7.12 xrdfs `ls -u/-D/-Z/-C` (URL entries,
per-entry kXR_Qcksum column, remote-ZIP member listing over the shared
bounds-checked parser, -D-as-identity; 5 cases in
`tests/test_xrdfs_locate_statq.py`) and §5.9 `brix_ztn_maxsz` (pre-crypto
bearer-credential size gate, default uncapped; `tests/test_ztn_maxsz.py`
distinguishes the size refusal from the validation refusal by error text).
Ladder 538→539 (lc-ztn-maxsz).
(l) **§1.13 QStats stock XML + §7.6 xrdcp --continue** — the stats document
now carries the stock wrapper and selector semantics (shape and letters
captured live from 5.6.9; sections filled from real counters, absent ones
omitted like stock's unknown letters; `tests/test_query_stats_xml.py`), and
--continue lands byte-offset download resume as the explicit opt-out of the
temp+rename discipline (new `copy_continue.c` over the resilient rfile pread;
partials survive failures, completed-but-corrupt files never do;
`tests/test_xrdcp_continue.py`, xrdcp(1) + usage updated). Details in the
§1.13 / §7.6 rows.
(m) **parity-fix wave 7 — §3.9 `oss.maxsize` create-size cap**: a shared
`brix_write_within_maxsize` helper refuses a data write whose end offset
crosses `brix_oss_maxsize` with kXR_overQuota, wired into all three native
write handlers (writev checks every segment before writing any, so a partial
vector can't leak). Load-bearing at the write plane, not just the oss.asize
open hint; default 0 = uncapped. `tests/test_oss_maxsize.py` (raw-wire
boundary + xrdcp integration + writev-crossing security-neg), directives.md
entry, registry-guard clean. Ladder 539→540 (lc-oss-maxsize).
(n) **parity-fix wave 8 — §6.6 WebDAV HTML directory listing on GET**:
`brix_webdav_html_listing on` renders an escaped HTML index (VFS
opendir/readdir seam shared with PROPFIND, dotfiles/sidecars hidden,
XML-escaped names), `brix_webdav_listing_redirect <url>` is the listingredir
301 analog, neither = the stock listingdeny 403. The GET open-and-stat helper
was kept side-effect-free (signals directory via NGX_DECLINED) so
`get_serve_directory` owns the response — no send buried in the stat helper.
`tests/test_webdav_html_listing.py` (4 cases incl. an inject/hide
security-neg), two directives.md entries. Ladder 540→541 (lc-html-listing).

(n) **§7.7 client fork-safety** — conn registry + pthread_atfork child
neutering (no goodbye bytes, unflushed abandonment, non-retryable errors),
`brix_conn_usable()` re-dial seam adopted by the preload shim; proven by a
real fork() through the shim (`tests/test_client_forksafe.py`). Details in
the §7.7 row.
(o) **parity-fix wave 9 — §3.2 `oss.cgroup` configurable name**: the
kXR_Qspace report hardcoded `oss.cgroup=default`; `brix_oss_cgroup <name>`
(default "default") now sets the advertised space-group name so accounting
keyed on the label works for a single-partition site. The config setter
rejects any CGI-structural byte (`& = space`/control) so a name can't inject a
second oss.* key into the "&"-joined report. Full multi-partition `oss.space`
groups + create-time CGI selection stay the larger §3.1 feature.
`tests/test_oss_cgroup.py` (raw-wire Qspace: configured/default/injection-
refused trio), directives.md entry, registry-guard clean. Ladder 541→542
(lc-oss-cgroup).

(o) **§7.13 closure wave** — -F/--coerce (kXR_force on the wire),
--retry-policy force|continue (retries resume via the --continue engine;
sever-shim differential in `tests/test_xrdcp_coerce_retry.py`), the -p/--path
row corrected as nonexistent in stock 5.6.9, and the stock-vs-BriX
--parallel semantic collision documented. Continue-mode reads now move in
1 MiB chunks so a severed attempt loses at most one chunk of progress.
(p) **parity-fix wave 10 — §6.9 `brix_webdav_tpc_xfr` explicit TPC
concurrency cap**: `brix_tpc_registry_add` gained a `max_active` parameter —
a new WebDAV COPY beyond N in-flight transfers is refused (registry returns 0
→ 503), counting LIVE in-use slots (a reap runs first so an abandoned
transfer never permanently counts against the cap). Wired into both WebDAV
register paths (sync + threaded); native root:// TPC passes 0 (unchanged).
Default 0 = slot-ceiling only. Deterministic C unit
`tests/c/test_tpc_xfr_cap.c` over the real SHM registry
(cap/refuse/release/uncapped), plus a runner tier + pytest entry; the sibling
`tpc_progress_total` unit confirms the signature change is clean. No lifecycle
server, so no ladder change. directives.md entry.

(p) **§7.13 --xattr + §7.12 spaceinfo** — user-namespace extended-attribute
preservation across root://<->local copies (kXR_fattr plane, namespace-walled
so kernel-namespace names never cross), and a new xrdfs `spaceinfo` verb
rendering stock 5.6.9's exact report shape from kXR_Qspace. New TU
`client/lib/xfer/copy_xattr.c`; `tests/test_xrdcp_xattr_spaceinfo.py` (6
cases). Details in the §7.12/§7.13 rows. This effectively CLOSES §7.13 (only
TPC/web-path cksum remains) and the xrdfs df-alias residual.
(r) **parity-fix wave 11 — §1.10 `brix_fsoverload_stall`**: the
memory-budget-overload backoff was a hardcoded `kXR_wait(1)`;
`brix_fsoverload_stall <n>` (default 1, the historical value) now sets it at
all three budget-overload sites (`read_buffered.c` ×2, `readv.c`), composing
with the wave-3 `brix_max_delay` clamp. `tests/test_fsoverload_stall.py`
drives a deterministic 2-connection budget-overload trigger (reader A holds a
large undrained read whose scratch charge exceeds a 256k budget, reader B is
deferred and observes the configured seconds): configured/default/max_delay-
clamped trio. fsoverload's redirect-host + bypass actions remain open.
Ladder 542→543 (lc-fsoverload).

(q) **§7.17 local→local + file:// copy** — the rejected copy direction now
works for every local/stdio pair via the new `copy_l2l.c` over the shared
transfer pump (atomic temp+rename for file destinations, -f/--xrate/--cksum
honored). Entirely fleet-free tests. Details in the §7.17 row.
(s) **parity-fix wave 12 — §4.6 sd_xroot chmod forwarding**: a chmod on a
proxy/cache export whose backend is a remote `root://` origin used to be a
SILENT no-op — `brix_vfs_chmod` found sd_xroot had no `.setattr` slot and
returned success without touching the origin. sd_xroot now carries
`.setattr`/`.setattr_cred` slots that forward `attr->set_mode` to the origin
via a new `brix_cache_origin_chmod` (kXR_chmod by path, mode BE16, mirroring
the existing origin rename/truncate helpers); times/owner stay a no-op
success (the remote node owns its own timestamps). `_check_chmod` added to
`tests/test_cmd_xroot_gateway_regress.py` (an origin+proxy harness): wire-ok,
the origin's on-disk mode actually changes to 0600, and a missing-path chmod
surfaces the origin's error instead of a false success. Server-side only — no
directive, no lifecycle server, no ladder change. (statfs/Stats forwarding —
the other half of §4.6 — followed in wave 13, item (t).)

(r) **§7.18 client asyncms + §1.6 correction** — the client now handles an
unsolicited kXR_attn(asyncms) server-push message instead of failing the
in-flight operation over it (`recv_handle_attn` in frame.c, printable-only so
server text can't inject tty escapes; MITM-injection test). Using the now-
available stock XProtocol.hh as the oracle, two audit rows were corrected as
newer-than-5.6.9: the other attn actions are all "No longer supported", and
§1.6's stat-wants / open-optiont fields simply don't exist in the 5.6.9
`ClientStatRequest`/`ClientOpenRequest`. Details in the §1.6/§7.18 rows.

(s) **§7.15 per-segment readv** — client can now scatter-gather one kXR_readv
across multiple open files (per-segment fhandle, matching stock's
readahead_list); `brix_file_readv_multi` + `xrdfs readvm`. The server already
supported it. Details in the §7.15 row.

(t) **parity-fix wave 13 — §4.6 sd_xroot statfs forwarding (completes §4.6)**:
the root kXR_Qspace handler reported the LOCAL export's statvfs even for a
backend whose real capacity lives elsewhere, and the `brix_vfs_space` seam
(implemented by pblock, phase-83 F5) had ZERO callers — so pblock's quota view
was invisible too. `brix_query_space` now consults `brix_vfs_space` first
(statvfs fallback when no driver reports space), and sd_xroot grew a `.space`
slot forwarding kXR_Qspace to the origin via a new `brix_cache_origin_space`
(kXR_query/Qspace by path, oss.* reply parsed with the shared grammar).
`tests/test_qspace_driver.py` uses a pblock `?quota=150m` as the discriminator
(distinct from host statvfs): the pblock export reports its quota, an
sd_xroot proxy over a pblock-quota origin forwards that 150 MiB, and a plain
posix export falls back to statvfs. Server-side only; 4 lifecycle subjects,
ladder 543→547. (The companion kXR_QFSinfo report — the compact "wVal freeMB
util" that CMS/kXR_locate actually reads to pick a writable server — still read
the LOCAL statvfs after this wave; wave 14, note (v), routes it through the same
seam and genuinely closes §4.6.)

(t) **§7.12 xrdfs REPL scriptability + §1.4 correction** — the interactive
shell skips `#` comments/blank lines and gates its prompt on a stdin TTY, so
piped command scripts produce clean stdout (`tests/test_xrdfs_repl_script.py`,
pty-verified). Using the stock XProtocol.hh oracle, §1.4's kXR_protocol row
was corrected: the TLS bits and secreqs response are already handled, and
bifreqs/secvec are architecturally N/A for a single-listener server. Details
in the §1.4/§7.12 rows.

(u) **§7.12 xrdfs xattr stock grammar** — the stock `xattr <path> <code>`
form (set/get/del/list, set=name=value) is accepted alongside BriX's own
`xattr <code> <path>`, closing the last xrdfs grammar incompatibility; a
stock-form call used to mis-list. New `xrdfs_xattr.c` (TU split for the size
gate); `tests/test_xrdfs_xattr_grammar.py`. Details in the §7.12 row.

(v) **parity-fix wave 14 — §4.6 QFSinfo forwarding (genuinely closes §4.6)**:
wave 13 routed kXR_Qspace through the driver-space seam but left kXR_QFSinfo —
the compact "wVal freeMB util sVal freeMB util" report that CMS's cluster
manager and kXR_locate read to select a WRITABLE server — still answering from
the proxy's LOCAL statvfs. A proxy over a full/quota-bounded origin therefore
advertised its own (empty) cache disk as free write space, exactly the wrong
signal for redirect selection. Both handlers now share one `query_space_probe`
(driver `brix_vfs_space` first, local-statvfs fallback), so Qspace and QFSinfo
can never disagree about which store a proxy is advertising. `brix_query_fsinfo`
reports the origin's / pblock quota's free space and utilization; a plain POSIX
export still declines the seam and reports host statvfs unchanged.
`tests/test_qspace_driver.py` now asserts BOTH reports against each live backend
(pblock-quota seam / sd_xroot proxy-forward / posix-fallback) — the QFSinfo
freeMB is quota-bounded where the seam fires and host-sized where it falls back.
Server-side only; no new lifecycle subjects (reused wave 13's), no ladder change.

(v) **§7.20 xrdcks tool** — a correct XrdCks checksum-in-xattr manager
(get/set/delete over the byte-exact 96-byte XrdCksData record), new xrdcksum
personality, fleet-free tests. En route the stock `xrdcks` CLI was found buggy
on this build (segfault on get, leading-byte drop on set), so BriX matches the
stable FORMAT not the flaky tool; BriX's xrdadler32/xrdcrc32c were confirmed
byte-for-byte drop-in with stock. Details in the §7.20 row.

(w) **§7.8 preload write path** — the LD_PRELOAD POSIX shim can now UPLOAD:
a write-only open under the BRIX_VMP prefix streams to the server and commits
on close (`cp file /xrd/…`, direct open+write). Read-only shim fds refuse
writes and vice-versa. Documented limit: fake fds don't survive dup2, so
shell redirection is out of scope (same as the read path). New write/pwrite
interceptors in `client/preload/brixposix_preload.c`;
`tests/test_preload_write.py`. Details in the §7.8 row.

(x) **parity-fix wave 15 — §2.4 cms.space min configurable**: the mSpace field
a data node advertises in its kYR_login payload — the free-space policy floor
below which the manager should stop selecting the node for writes — was the
hardcoded `NGX_BRIX_CMS_MIN_FREE_MB` (100). `brix_cms_min_free <MB>` now sets
it (`cms.min_free_mb`, merged default 100 = byte-identical to the constant),
emitted in `src/net/cms/send.c` in place of the literal. Absolute MB only (the
stock percentage form is not taken). Verified straight off the LOGIN wire with
the existing CMS Pup-conformance harness: a new node template + ledger subject
(`lc-cms-wire-minfree-node`, shared ladder 547→548) whose captured login
decodes to the configured mSpace. `tests/test_cms_wire_pup_conformance.py::TestLoginMinFree`
— default-100 (a node with no directive still emits 100), configured value
reaches mSpace (250250 MB, a >16-bit value proving it rides as a full 32-bit
PT_INT), and layout-integrity (the enlarged field neither shifts nor overflows
the fixed CmsLoginData scalar/4-string tail). Server-side only. Strikes the
"configurable min" clause of §2.4 (hysteresis/linger/recalc/mwfiles remain).

(y) **parity-fix wave 16 — §3.15 OssStats slowop classifier**: op latency was
booked into the histogram at completion but never classified as "slow" — a
dashboard had to re-derive slow-op counts from fixed histogram buckets rather
than the operator's own threshold. `brix_metrics_slowop <usec>` arms a latency
threshold that is stamped once per config load into the metrics SHM
(`unified.slowop_threshold_usec`) at init_module — the master reads it off the
stream conf via the cycle, so the lock-free latency record path in every worker
classifies without a config pointer. Any op whose measured latency meets/exceeds
the threshold is booked into `brix_io_slowop_total{proto,op}`, and the armed
value is exported as the `brix_io_slowop_threshold_usec` gauge; 0 (default)
disables the classifier with zero counter movement (byte-identical to before).
Microseconds (not a time token) so a fine threshold is expressible. All
edit-only — no new TU, no reconfigure, no census change; the counter rides the
existing unified SHM struct and the latency record path already on the hot path.
`tests/test_metrics_slowop.py` drives one node at three thresholds (1µs → the
AIO write is booked; 0 → classifier off, no series; 1h → the sub-second write is
NOT booked, proving the latency is genuinely compared) scraped off `/metrics`;
the existing recorder-internals guard was widened to admit the new low-
cardinality counter. Server-side only; shared ladder 548→550 (lc-slowop + its
METRICS_PORT). Strikes the "slowop threshold classifier" clause of §3.15 (the
mid-op in-flight duration increments remain).

(z) **§1.9 POSC persist policy (`ofs.persist` analog)** — the boot-time reaper
that clears crash-orphaned `<final>.xrd-tmp.<pid>.<rand>` upload temps already
existed (phase-64 SP4, `core/compat/tmp_path.c brix_tmp_reap_all` at worker-0
init; dead-owner orphans removed, live-owner in-flight writes kept — reload-safe),
so the audit row's "boot scrub" half was stale. What was missing is stock's
governing knob: `brix_posc_persist <auto|manual|off> [hold <time>]`. `auto`
(default) reaps as before; `manual`/`off` KEEP orphans for an operator to
inspect/recover; `hold <time>` is a grace period so a temp whose writer is about
to reconnect-and-resume is not reaped mid-recovery (mtime-age gate; a future
mtime counts as fresh). Node-global policy set at parse — last explicit wins, an
undirected block never clobbers a directed one, and a reload that removes the
directive keeps the last value until restart (fail-safe: orphans kept, never a
wrongful delete). `fs/cache/directives.c` (`brix_conf_set_posc_persist`) +
`directives_writethrough.h` + the reaper honoring in `tmp_path.c`; all edit-only,
no new TU / no reconfigure. `tests/test_posc_persist.py` — reaper behaviour as a
C unit test against the real `tmp_path.o` (5 scenarios incl. the security-neg
that only `.xrd-tmp.` names are ever touched) + `nginx -t` accept/reject of the
grammar. Strikes the `ofs.persist` clause of §1.9 (mid-op nothing else remains
there).

(aa) **parity-fix wave 17 — §5.10 xrd.tlsca `verdepth` (stream listener)**: the
GSI chain verifier `brix_gsi_verify_chain` already accepted a depth cap
(`verify_depth > 0` → `X509_STORE_CTX_set_depth`), but the root:// GSI
cert-login caller in `auth/gsi/auth_cert.c` passed a hardcoded `0` (unlimited) —
so a client could present an arbitrarily deep proxy/intermediate chain. New
`brix_gsi_verify_depth <n>` (conf field `gsi_verify_depth`, num slot,
init/merge, default 0 = unlimited = byte-identical) now feeds that call. Server-
side only; all edit-only (no new TU, no reconfigure) — the enforcement primitive
already existed, only the config seam was missing. The behaviour is pinned as a
C unit against the REAL verify function over a forged deep chain (CA → 2
intermediate CAs → EEC → proxy): `tests/test_c_auth_units.py::test_c_auth_unit[gsi_verdepth]`
asserts uncapped-accept / depth-1-reject / depth-20-accept; `tests/test_gsi_verify_depth.py`
guards the config path (the login site forwards `conf->gsi_verify_depth`, and
`nginx -t` accepts a number / rejects a non-number). Strikes the "verdepth for
stream listener" clause of §5.10 (crlcheck last-scope, verification-log toggle,
tlsreuse, and stream tlsciphers remain).

(ab) **parity-fix wave 18 — §5.10 xrd.tlsciphers (stream listener)**: the
root:// in-protocol TLS context (`brix_configure_tls`) set a cert/key and TLS
version floor but never pinned a cipher list — so operators could not restrict
the root:// TLS ciphers for a compliance profile (nginx's `ssl_ciphers` only
governs the HTTP side). New `brix_tls_ciphers <list>` applies the list via
`SSL_CTX_set_cipher_list` (TLSv1.2-and-below, exactly nginx `ssl_ciphers`
scope/semantics; TLSv1.3 suites stay OpenSSL's defaults). A list matching NO
ciphers is a HARD config error, not a silent OpenSSL-default fallback, so a typo
can never leave the listener quietly more permissive than intended. Conf field
`tls_ciphers`, str slot, merge default "" (unchanged); all edit-only, no new TU,
no reconfigure. The root:// TLS is an in-protocol upgrade (not a raw listener) so
a bare s_client can't probe it, but `nginx -t` runs the real config-init cipher
application, making accept/reject an end-to-end proof the list reaches and
constrains the SSL_CTX: `tests/test_tls_ciphers.py` (valid-pinned /
unmatched-rejected / default-unchanged). Strikes the "xrd.tlsciphers for stream
listener" clause of §5.10 (crlcheck last-scope, verification-log toggle, and
tlsreuse remain).

(ac) **parity-fix wave 19 — §5.10 xrootd.tlsreuse (stream listener)**: the
root:// in-protocol TLS context left TLS session resumption at the OpenSSL/nginx
defaults (tickets on) with no operator control — a deployment wanting
per-connection forward secrecy (no resumption state to capture or replay) could
not turn it off. New `brix_tls_reuse on|off`: off clears the session cache
(`SSL_SESS_CACHE_OFF`) AND session tickets (`SSL_OP_NO_TICKET`) so every
connection full-handshakes; default on leaves the defaults (byte-identical). The
policy is a header-inline pure-OpenSSL helper (`session/tls_session.h`
`brix_tls_apply_session_reuse`) so `brix_configure_tls` applies it AND a
self-contained OpenSSL unit test exercises the exact same code without linking
the nginx-coupled TU — no new .c, no reconfigure. `tests/test_c_auth_units.py::test_c_auth_unit[tls_reuse]`
(off ⇒ cache OFF + NO_TICKET set / on ⇒ inert / NULL-safe, against a real
SSL_CTX) + `tests/test_tls_reuse.py` (wiring: `brix_configure_tls` forwards
`conf->tls_reuse`; config-init runs the off branch; default keeps resumption).
Strikes the `xrootd.tlsreuse` clause of §5.10 (crlcheck last-scope and
verification-log toggle remain — both fuzzier/lower-value; the two clean §5.10
knobs, verdepth+tlsciphers+tlsreuse, are now done).

(ad) **parity-fix wave 20 — §5.10 xrd.tlsciphers TLSv1.3 completion**: wave 18's
`brix_tls_ciphers` only governs the TLSv1.2-and-below cipher list
(`SSL_CTX_set_cipher_list`), leaving TLSv1.3 suites at OpenSSL's defaults — but
TLSv1.3 is today's default protocol, so an operator restricting ciphers for a
compliance profile could not actually constrain a modern root:// TLS connection.
New `brix_tls_ciphersuites <list>` applies the TLSv1.3 suite list via
`SSL_CTX_set_ciphersuites` (the independent OpenSSL knob), with the identical
config-init guarantee: a list matching no suites is a hard config error, never a
silent default fallback. Conf field `tls_ciphersuites`, str slot, merge default
"" (unchanged); edit-only, no new TU, no reconfigure. `tests/test_tls_ciphers.py`
gained the TLSv1.3 trio (valid-pinned / unmatched-rejected / default-unchanged,
via the same `nginx -t` config-init proof). Completes the "xrd.tlsciphers for
stream listener" clause of §5.10 the wave-18 note had explicitly deferred for
TLSv1.3.

(ae) **parity-fix wave 21 — §1.12 prepare `prty` observability**: the kXR_prepare
request priority byte is decoded into `req.prty` but was silently dropped from
every observability surface — the PREPARE access-log detail logged
opts/optx/paths but not the priority, so an operator could not see what priority
clients requested. It now rides the detail as `prty=<n>` (`query/prepare.c`, one
`snprintf`; edit-only). `tests/test_prepare_prty.py` sends prepares at prty=7 and
prty=0 and asserts each surfaces on its PREPARE log line (+ a source wiring
guard). This is a small, honest step, NOT a close: HONOURING prty in scheduling
stays N/A for BriX's model — it stages disk immediately (reads fault the file in)
and FRM, where a priority queue would live, was dissolved, so there is no
contended stage queue for a priority to order. **A candour note: after waves
13–20 the cleanly-implementable, safe, non-colliding audit items are largely
exhausted; the remaining rows are architectural (space groups, OssArc,
per-subtree attrs), deliberate/N-A (ztn expiry modes, cms.fsxeq, pfc.urlcgi),
wire-format-risky without the XProtocol oracle (login ability), in the parallel
session's live zones (authdb, cache, oss.quota), or need heavy infra (accept-time
rDNS for cms.allow, a CRL-forging + cache-keyed store rework for crlcheck). Future
waves here will be marginal unless scoped to one of those larger items.**

Also collected en route: a dead-code/doc-drift punch list (§9.2–§9.3) including dormant
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
| 1 | **pathid response offloading** (do_Offload/do_OffloadIO parity): read/readv/write/pgread/pgwrite pathid decoded (`codec/wire_codec_file.c:161,189`) but no handler routes response data over bound streams; kXR_AnyPath too | PARTIAL (**read-family offload landed 2026-08-10**: conn map + read/readv/pgread pathid validate + kXR_read/kXR_readv/kXR_pgread responses ROUTED over the secondary; write offload + multi-worker fd-passing remain) | `connection/send.c`, `session/bind.c`, fd-table sharing — the one substantive data-path gap. **Slice 1** (foundation): the SHM session registry already tracks WHICH pathids a session bound (`brix_session_pathid_bound`, cross-worker), but routing a response needs the secondary's process-local `ngx_connection_t`, which cannot live in SHM. New per-worker `(sessid,pathid)→conn` map (`session/offload_registry.{c,h}`, pure/unit-tested): `kXR_bind` registers the secondary (`bind.c`), disconnect clears it (`connection/disconnect.c`, keyed by the closing conn). Populated but NOT yet consumed → zero data-path change. `tests/test_offload_registry.py` (C unit: register/lookup/replace/unregister, pathid-0 + miss cases, NULL guards, bounded-capacity refusal). **Slice 2a** (landed): `kXR_read` now DECODES and VALIDATES its optional `read_args` pathid (payload byte 0 when dlen ≥ 1) exactly as pgread/§1.2 does — a nonzero pathid must name a live `kXR_bind` path of this session (`brix_session_pathid_bound`), else `kXR_ArgInvalid` "invalid path ID"; the validated pathid is captured on `brix_read_io_t.pathid` for the routing slice. Closes a read-vs-pgread inconsistency (kXR_read previously ignored `read_args` outright, while pgread already validated). `read/read.c` `read_validate_req`, `read/read_internal.h`; `tests/test_session_bind.py::TestReadPathidValidation` (pathid-0 served, unbound pathid ⇒ kXR_ArgInvalid — verified live; the valid-bound-pathid case is now the offload success test below). **Slice 2b** (landed for kXR_read): `brix_handle_read` now consults `brix_offload_lookup(sessid, pathid)` and, when the bound secondary is on this worker AND quiescent (no queued response / async-ack / in-flight AIO, live fd), serves a single-frame (≤ one streaming window) read's response over the SECONDARY's socket — carrying the PRIMARY request's streamid — via an isolated early-dispatch `brix_read_try_offload` (`read/read.c`). The response buffer is acquired AND released on the secondary's ctx (which already runs this out-ring queue/drain machinery for its own bound reads), so there is no cross-connection buffer-lifetime tangle. Every ineligible read (pathid 0, cross-worker, busy secondary, large/windowed) falls through to the normal primary-stream strategies, byte-identical to before. `tests/test_session_bind.py::TestReadResponseOffload` (response routed to the secondary carrying the read's streamid; pathid-0 stays on the primary; large read falls back to windowed primary) — verified live 16/16 with the full bind suite as regression. **kXR_readv** (landed): same treatment — readv carries its pathid in the request HEADER body (byte 15, not the payload); `brix_handle_readv` now validates it (nonzero ⇒ must be bound, else `kXR_ArgInvalid` — readv previously ignored it) and, when eligible, `brix_readv_try_offload` (`read/readv.c`) assembles the whole multi-segment response into a secondary-owned buffer and routes the single kXR_ok frame over the secondary carrying the primary streamid. `tests/test_session_bind.py::TestReadvResponseOffload` (unbound ⇒ kXR_ArgInvalid; bound pathid ⇒ 3-segment response on the secondary, stripped payload byte-exact; pathid-0 stays on primary) — 19/19 live. **kXR_pgread** (landed): pgread already validated its pathid (§1.2); `brix_pgread_try_offload` (`read/pgread.c`) now routes an eligible reply — the two-part `[32B kXR_status frame | CRC-interleaved page data]` — over the secondary as one contiguous secondary-owned flat buffer (encode straight into `buf+32` via the shared `brix_pgread_sync_fill`, stamp the status frame with the primary streamid, queue on the secondary). `tests/test_session_bind.py::TestPgreadResponseOffload` (unbound ⇒ kXR_error; bound ⇒ kXR_status reply on the secondary, CRC-stripped data byte-exact; pathid-0 stays on primary) — 22/22 live. **Pipelining relaxation** (landed): the eligibility gate no longer requires a fully idle secondary — it now offloads whenever the secondary's out-ring has a free slot under COMPLETE reserved-slot accounting (`out.count + out.wr_inflight + rd.aio_inflight < pipeline_depth`, and not mid-async-ack). So a burst of pathid reads on the primary keeps landing on the data channel while an earlier large reply is still draining (the real multi-stream pattern), instead of falling back to the primary after the first. Provably overflow-free (every queued + in-flight response is counted, frames drain head-first); a full ring still backpressures to the primary. `tests/test_session_bind.py::TestOffloadPipelining` (a parked large reply + a second read that must stay on the secondary — verified to FAIL under the old idle-only gate and PASS under the new one, with the server `sndbuf` constrained to force the park). **Observability** (landed): each offloaded reply books `brix_io_offload_total{proto="stream"}` (`brix_metric_offload`, incremented in all three `*_try_offload` on a successful secondary queue; exported in `unified_export_io.c`), so an operator can confirm offloading is live and measure its rate — absent until the first offload. `tests/test_offload_metric.py` (offloaded read ⇒ counter==1; plain read ⇒ series absent). STILL OPEN: **write** response offload (a different mechanism — write's pathid selects the stream the client SENDS data on, so it is a recv-path change, not response routing), and the multi-worker case (secondary on another worker needs SCM_RIGHTS fd-passing) — both fall back to the control stream today |
| 2 | ~~pgread request args: pathid + `kXR_pgRetry` (client re-requests corrupt pages)~~ | **LANDED 2026-08-10** | Payload parsed exactly as stock 5.6.9 does (verified live against a private stock instance): pathid at byte 0 when dlen ≥ 1, reqflags at byte 1 when dlen ≥ 2, extra bytes and unknown flag bits tolerated, `kXR_pgRetry` served as a fresh-CRC re-read. The one behavioral rule — a nonzero pathid must name a LIVE `kXR_bind` path of this session, else `kXR_ArgInvalid` "invalid path ID" — is enforced via a new per-session bound-pathid bitmap in the SHM session registry (`registry.{h,c}` `brix_session_pathid_{bind,unbind,bound}`, set at bind, cleared on the secondary's disconnect — also the groundwork for §1.1 response offloading, which remains open: responses still travel the control stream). `read/pgread.c`, `session/bind.c`, `connection/disconnect.c`; differential + lifecycle tests `tests/test_conf_pgio_b.py::test_pgread_args_*` (6 cases) |
| 3 | Login `ability`/`ability2` honored: kXR_fullurl, kXR_redirflags, hasipv64/onlyprv4/6 addr-family redirect variants, lclfile | MISSING (decoded, ignored) | store in ctx at `session/login.c`, branch `response/control.c` |
| 4 | kXR_protocol negotiation — **mostly N/A / already-done (row corrected 2026-08-10 via stock XProtocol.hh)**: per-plane TLS bits ARE advertised (§5.3 landed, kXR_tlsLogin/Sess/Data/TPC); kXR_secreqs response IS returned (`session/protocol.c:196-219`). Of the residue, the oracle shows `kXR_bifreqs` bind-interface info "will not be returned if there are no bif's" — a single-listener nginx has none, so omitting it is spec-compliant; the per-request `secvec` is optional (the valid `secvsz=0`+seclvl form BriX sends is complete for a uniform signing level). Only the advisory `expect` byte is genuinely unparsed, and it is safely ignorable. | N/A-mostly | `session/protocol.c` |
| 5 | ~~Missing error constants: kXR_SigVerErr(3022), DecryptErr(3023), BadPayload(3026), noReplicas(3029), ReqTimedOut(3034), TimerExpired(3035)~~ | **LANDED 2026-08-09** | Defined in `protocol/opcodes.h`, named in `core/compat/kxr_names.c`, mapped in `core/compat/error_mapping.c` (SigVer/Decrypt→EACCES, BadPayload→EINVAL, noReplicas→EHOSTUNREACH, both timeouts→ETIMEDOUT), and the three TRANSIENT ones (noReplicas/ReqTimedOut/TimerExpired) now classify RETRYABLE in the client (`status.c`) — a stock server's timeout used to abort the whole transfer. BriX's own sigver responses deliberately keep sending kXR_NotAuthorized (wire-compat with the locked `test_sigver_*` suites). Unit: `client/tests/c/kxr_errors_unit.c`. |
| 6 | ~~stat `wants`/kXR_Want_btime extended mask; open `optiont` (retstatx/directio/dup/samefs) decoded-not-acted~~ | **N/A for 5.6.9 (row corrected 2026-08-10)** | Oracle check (stock XProtocol.hh): 5.6.9's `ClientStatRequest` has NO `wants` field (just `options`=kXR_vfs then `reserved[11]`) and `ClientOpenRequest` has NO `optiont` field (`reserved[12]` after `options`). These are newer-than-5.6.9 additions; against the 5.6.9 interop baseline the bytes are reserved and BriX correctly treats them as such — not a parity gap. (The audit was written against a newer upstream tree, since gone.) |
| 7 | ~~dirlist `kXR_online` filter masked out~~ | **LANDED 2026-08-09** (parity-fix wave) | `handler_stream.c` `brix_dirlist_entry_not_online()`: when the bit is set every file entry is probed through the SAME `brix_vfs_residency()` walk stat/statx advertise kXR_offline through (one authority, no drift) and NEARLINE/OFFLINE entries are omitted; directories always pass; probe errors fail open (entry listed). `tests/test_dirlist_online.py` (4 cases over the pblock `?nearline=1` lab, incl. dstat-leak security-neg) |
| 8 | locate options: ~~refresh~~ **LANDED 2026-08-09** via §2.7 (`locate.c:71` decodes kXR_refresh; `locate_manager.c` flushes + bypasses the loc and collapse-redir caches); ~~nowait~~ **LANDED 2026-08-10** — a kXR_nowait locate is never parked: the existence fan-out fires with a streamid nothing waits on (an accepted kYR_have is cache-only per `cms_srv_frame_have`) and the client gets kXR_wait immediately, so its retry hits the warm loc cache (`locate_manager.c` `locate_try_dynamic`; `tests/test_cms_parity_wave.py::test_nowait_locate_never_parks` — immediacy, fan-out-still-fires, cache-only HAVE→redirect, `..`-reject unaffected); 4dirlist/compress still parsed-then-discarded | PARTIAL | `read/locate.c` |
| 9 | ~~POSC crash-orphan scrub at boot~~ (already landed, phase-64 SP4) + ~~`ofs.persist {auto\|manual\|off} [hold]` policy~~ | **LANDED 2026-08-10** (wave x) | The boot scrub already existed and the row was stale on it: `core/compat/tmp_path.c brix_tmp_reap_all` runs at worker-0 init (`config/process.c`), nftw-walks every registered export root, and unlinks a `<final>.xrd-tmp.<pid>.<rand>` orphan whose owner pid is DEAD — a temp whose owner is still live (a draining worker mid-reload) is kept, so it is reload-safe by construction. NEW this wave is the **`ofs.persist` policy** governing it: `brix_posc_persist <auto\|manual\|off> [hold <time>]` (`fs/cache/directives.c`, `directives_writethrough.h`). `auto` = the historical reap; `manual`/`off` KEEP orphans for an operator to inspect/recover; `hold <time>` is a grace period — an orphan is reaped only once idle at least `<time>` (mtime age, future-mtime treated as fresh), so a temp whose writer is about to reconnect-and-resume is not reaped mid-recovery. Node-global (the reaper runs once), set at parse: last explicit directive wins, a block without it never clobbers one with it; a reload that removes it retains the last explicit value until restart (fail-safe: "orphans kept", never a wrongful delete). Tests `tests/test_posc_persist.py` — the reaper behaviour as a C unit test against the real `tmp_path.o` (auto reaps dead-owner / keeps live-owner + non-`.xrd-tmp.` files, manual+off keep, hold spares-fresh-then-reaps-aged, and the security-neg that only `.xrd-tmp.` names are ever touched) + `nginx -t` accept/reject for the grammar. Still open (unchanged): the POSC `persist [hold]` *keep* semantics here cover orphan recovery; there is no separate durable POSC-state journal (BriX POSC is temp+fsync+rename, not a tracked-file DB — `manual`/`off` collapse to "don't reap", documented divergence) |
| 10 | `xrootd.fsoverload` (~~stall n~~ / ~~redirect host~~ / bypass); ~~`ofs.maxdelay` clamp as config policy~~ maxdelay **LANDED 2026-08-09** (parity-fix wave 3), fsoverload **stall LANDED 2026-08-10** (parity-fix wave 11), **redirect LANDED 2026-08-10** | PARTIAL (bypass still open) | `brix_max_delay <time>` (default 60s = stock) clamps the seconds of EVERY kXR_wait at the single emission choke point (`response/control.c brix_send_wait`, cached in ctx at accept); 0 disables. `tests/test_max_delay.py`. **fsoverload stall** (§1.10): `brix_fsoverload_stall <n>` (default 1 = the historical hardcoded value) sets the seconds a memory-budget-overloaded read/readv tells the client to back off — replaced the hardcoded `kXR_wait(1)` at all three budget-overload sites (`read_buffered.c` ×2, `readv.c`); still clamped by `brix_max_delay`. `tests/test_fsoverload_stall.py`. **fsoverload redirect**: `brix_fsoverload_redirect <host> <port>` — on a budget overload the read/readv is answered with a kXR_redirect to that sibling (offload the read) INSTEAD of the stall; "" = off = stall. The three overload sites now share one `brix_fsoverload_backoff` helper (`read/read.c`, declared in `read.h`) that redirects-if-configured-else-stalls; `<host> <port>` (two tokens, not host:port) is a documented spelling divergence. `tests/test_fsoverload_stall.py::test_overload_redirect` (the 2-connection budget-overload trigger, asserting B gets kXR_redirect to host:port not kXR_wait). The fsoverload **bypass** overload action (serve anyway despite overload) remains open — deliberately, since bypassing the memory budget invites OOM |
| 11 | ~~chkpoint `ofs.chkpnt maxsz` knob (cap fixed at kXR_ckpMinMax)~~ | **LANDED 2026-08-09** (parity-fix wave 2) | `brix_chkpnt_maxsz <size>`: ckpBegin refuses above it (kXR_overQuota), ckpQuery reports it as maxCkpSize (u32-clamped), merge floors below-minimum values at kXR_ckpMinMax — the "minimum maximum" every server must accept. `tests/test_chkpnt_maxsz.py` (raised/default/floored postures), documented in directives.md |
| 12 | prepare `prty` priority (now **surfaced**, wave 21; scheduling still N/A) + UDP notify callback (`port`/kXR_usetcp); `xrootd.prep keep/scrub/logdir` | PARTIAL | in-band asyncms substitutes. **prty**: the decoded request priority was silently dropped from all observability; the PREPARE access-log detail now carries `prty=<n>` (`query/prepare.c`; `tests/test_prepare_prty.py` — prty=7/prty=0 surface on the log line + a wiring guard). HONOURING prty in scheduling stays N/A: BriX stages disk immediately (reads fault the file in), and FRM — where a priority queue would live — was dissolved, so there is no contended stage queue for a priority to order. UDP notify + prep keep/scrub/logdir remain |
| 13 | ~~QStats format: abbreviated counters, not stock XML `<statistics>` doc — XML-parsing clients fail~~ | **LANDED 2026-08-10** | `query/metadata.c` now emits the stock wrapper (`tod ver src tos pgm ins pid site` root attributes, shape captured live from 5.6.9; the spurious `id=` is gone) and honors the stock selector letters (a/i/l/p verified live; b/d/s/u name sections BriX has no data for and contribute nothing, exactly like an unknown letter on stock). Sections filled honestly from real state: info, link, xrootd (ops from the per-op metric slots, misc/err aggregating the unmapped ones so totals stay truthful), ofs role, oss v=2 (live statvfs of the export), sgen; absent counters emit 0, never inventions; ver/pgm keep the BriX identity. `tests/test_query_stats_xml.py` (well-formedness + root attrs, ops/rd moves after a served read, subset selection, 400-byte hostile selector stays bounded) |
| 14 | ~~Qconfig key-for-key parity (bind_max, pio_max, readv_ior_max, sysid, wan_port, window…; unmatched keys must echo)~~ | **CLOSED 2026-08-09** | bind_max/pio_max/readv_ior_max/role/fattr + unknown-key echo landed earlier; `window` landed 2026-08-09 (live SO_RCVBUF of the session, bare integer). sysid/wan_port/wan_window/sitename/cid verified live against stock 5.6.9 (default config): stock ECHOES them unset, BriX's echo fallback is byte-identical, and no BriX directive sets them — echo is the permanent faithful answer. `query/config.c`, `tests/test_query_extended.py::TestQconfigStockKeyParity` |
| 15 | ~~Query-by-fhandle (do_Qfh Qcksum/Qxattr on open handle)~~ | **RESOLVED 2026-08-10 — PRESENT as a SUPERSET** | Live differential vs stock 5.6.9: stock NEVER serves Qcksum/Qxattr purely by fhandle — a valid open handle with an empty payload gets kXR_ArgMissing "Required query argument not present"; BriX's by-fhandle Qcksum genuinely computes (same digest as by-path, `checksum_qcksum.c` routes on empty payload — the row's "dispatch keys on infotype only" was looking at the wrong layer). Every error CODE matches stock (non-open fhandle → kXR_FileNotOpen both sides; message text differs, codes are what clients parse). Pinned by `tests/test_query_by_fhandle.py` (4 cases incl. the stock half of the differential when the ref server is up, and a foreign-session-fhandle security-neg) |
| 16 | ~~XrdXrootdAdmin unix-socket admin (abort/cont/disc/msg/pause)~~ | **LANDED 2026-08-10** (slices 1+2+multi-worker, user-selected) | `brix_admin_socket <path>` opens a worker-0 unix control socket (`session/admin_socket.{c,h}`, init from `process.c`) speaking a line-based protocol — DOCUMENTED DIVERGENCE: stock's admin wire grammar is not published in installed headers, so the verbs match but not the bytes. `list` → every connection on the worker (sessions self-register `sessid→conn` in the per-worker offload registry under out-of-wire-range pseudo-pathid 255 at ctx setup — `connection/handler.c`, single site covering all 8 auth flavors AND pre-login conns, invisible to the data path since the SHM bound-path bitmap refuses >253 before any offload lookup; dn enriched via `brix_session_lookup`); `disc <sessid-hex>` → `shutdown(2)` on the session's socket so the normal event-loop teardown runs (no re-entrancy); `msg <sessid-hex> <text>` → unsolicited `kXR_attn`/asyncms via `brix_send_attn_asyncms` on the target's out-ring (the §1.1 cross-connection queue pattern). Socket chmod 0600 — filesystem permission IS the privilege boundary (stock adminpath semantics). Worker-0/local slice (complete under `worker_processes 1`; multi-worker reach needs the same SCM_RIGHTS/broker step as §1.1 — "err unknown-or-not-local" otherwise). `disconnect.c` now clears the per-worker map unconditionally by conn. GOTCHA for future nginx-socket work: `ngx_get_connection()` hands out a BARE connection — set `c->recv/c->send/c->send_chain/c->recv_chain` yourself or the first I/O is a NULL call. **Slice 2 (landed): pause/cont/abort.** `pause <sessid-hex> [<secs>]` sets `ctx->admin_paused`, honored at the TOP of the recv loop's handoff gate (`recv.c brix_recv_handoff_state`): yield WITHOUT reading or re-arming, so further requests back up in the kernel socket buffer (TCP backpressure) while in-flight responses keep draining — stock pause semantics; the optional `<secs>` arms a one-shot `ctx->admin_pause_ev` timer that self-resumes (deleted at disconnect next to `pmark.echo_ev` so it can never fire into a freed ctx). `cont` clears the flag and `ngx_post_event`s the read event (the paused loop never re-armed, so posting is mandatory to drain the backlog). `abort` = disconnect without ceremony: `SO_LINGER{1,0}` + `shutdown(2)` makes the teardown's eventual close send an RST, so the client sees ECONNRESET (vs `disc`'s clean FIN) — teardown still runs the normal event-loop path. **Multi-worker reach (landed, closes the row):** every worker serves its OWN socket — worker 0 at the configured `<path>`, worker n at `<path>.<n>` — each listing/controlling exactly the sessions its worker owns; an admin tool sweeps the socket set. The natural mapping of stock's single-daemon adminpath onto nginx's process model (documented divergence; no fd-passing needed — unlike §1.1's data-plane multi-worker gap, admin verbs execute where the session lives). `list` lines now carry the PEER ADDRESS (`<sessid-hex> <peer|-> <dn|->`) so an operator can pick a session. Tests `tests/test_admin_socket.py` (7: list(with peer)→msg(kXR_attn read off the client)→disc(EOF); pause gates a live read + cont serves the backed-up request byte-exact; timed pause auto-resumes with no cont; abort ⇒ ECONNRESET; unknown-sessid across all five verbs + bad-secs + bogus verb ⇒ err; socket mode 0600; worker_processes-2 sweep — session in exactly ONE worker's list, non-owner disc errs (isolation), owner disc lands) |
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
| 4 | cms.space: ~~configurable min (hardcoded 100MB)~~ (min now configurable), HWM re-eligibility hysteresis, linger, recalc, mwfiles | PARTIAL (wave 15) | `brix_cms_min_free <MB>` sets the mSpace policy floor advertised in the kYR_login payload — the free space below which the manager stops selecting this node for writes; was the hardcoded `NGX_BRIX_CMS_MIN_FREE_MB` 100, default stays 100 (byte-identical). Absolute MB only (stock's percentage form not taken). `tests/test_cms_wire_pup_conformance.py::TestLoginMinFree` (default-100 / configured-value-reaches-mSpace / layout-integrity trio, decoded off the LOGIN wire). HWM re-eligibility hysteresis, linger, recalc, mwfiles remain — the larger dynamic-space-state feature. |
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
| 2 | `oss.cgroup` CGI space selection at create; ~~`space.c` hardcodes `oss.cgroup=default`~~ (name now configurable); ~~`oss.quota=-1` still fixed~~ (quota now advertisable, wave 29) | PARTIAL (wave 9 / wave 29) | `brix_oss_cgroup <name>` (default "default") sets the space-group name the kXR_Qspace report advertises as `oss.cgroup`, so accounting keyed on the group label works for a single-partition site; the setter rejects any CGI-structural byte (`& = space`/control) so a name can't inject a second oss.* key. **`brix_oss_quota <size>`** (wave 29) likewise sets the `oss.quota` value the Qspace report advertises (default -1 = unlimited, byte-identical), so a site migrating from stock keeps its configured quota visible to `xrdfs query space` / accounting tools — advertisement only, BriX enforces no hard quota (`query/space.c`, `protocol/qspace.h` gained the quota arg, setter `module.c`, `off_t oss_quota` in `srv_conf_fields_cache.h` merged in `server_conf_merge_proxy_net.c`; `tests/test_oss_quota.py` configured/default/malformed trio). Full multi-partition `oss.space` groups + create-time CGI selection + real quota ENFORCEMENT remain the larger §3.1 feature. `tests/test_oss_cgroup.py` (configured/default/injection-refused trio) |
| 3 | Persistent usage ledger + quota outside pblock (pblock has full SQLite uid/gid rollup + EDQUOT; posix/S3/HTTP have statvfs only) | PARTIAL (**enforcement slice landed 2026-08-10, wave 41**) | **`brix_oss_quota_enforce on`** makes wave-29's advertised `brix_oss_quota` REAL: a kXR_write/writev/pgwrite whose length would push the export's usage past the quota is refused `kXR_overQuota` at the shared write-admission chokepoint (`write.c brix_write_within_maxsize`, the §3.9 oss.maxsize gate — zero call-site changes; the quota check runs independently of maxsize). Usage comes from the SAME probe the Qspace report advertises (`brix_query_space_probe`, exported from `query/space.c`): a driver `space` slot answers exactly (pblock catalog), plain POSIX falls back to statvfs of the export's filesystem — CONSERVATIVE on a shared mount, documented (a lab quota on a dedicated volume is the exact statvfs case). TTL-cached 5 s/worker (statvfs is cheap; the pblock catalog is SQLite — never per-write); probe FAILURE fails OPEN (quota is policy, not integrity). Default off = advertisement-only, byte-identical. `tests/test_oss_quota_enforce.py` (enforce-on admits under quota; enforce-on refuses over quota — xrdcp surfaces the `overQuota` wire error verbatim; default stays advertisement-only). REMAINING: the durable per-uid/gid usage LEDGER itself (accurate per-identity deltas at every size-changing chokepoint — the true XrdOssSpace file analog) + an exact-usage pblock test leg (its space slot's arming interacts with lazy instance build) |
| 4 | **Tape online-buffer purge policy** (frm_purged F1/F2): monitor logs only, never acts; MSS adapter has `purge` verb, nothing drives it; no external polprog | MISSING (explicit scope-out at FRM dissolution — revisit) | history-storage-and-caching.md §6 |
| 5 | **OssArc**: dataset→zip aggregation to tape, member-indexed recall, backup queue | MISSING | largest tape gap for small-file workloads; compose step in stage engine |
| 6 | RAM caches: oss.memfile mmap/mlock/preread; XrdRmc block cache; server-side preread policy | MISSING | natural fit as `ram:<size>` cstore driver |
| 7 | ~~MSS namespace gateway: sd_frm dirlist/opendir + rcreate~~ | **LANDED 2026-08-10** (dirlist wave 35, rcreate wave 36) | The MSS adapter vtable gained an OPTIONAL `list` verb (`sd_frm.h` — the stock `rsscmd dread` analog; NULL slot ⇒ ENOTSUP, so adapters that can't enumerate keep the old behaviour) backing new `sd_frm` opendir/readdir/closedir slots (+`BRIX_SD_CAP_DIRS`; malloc-owned snapshot cursor — the frm instance has no pool). **stub**: readdir of the local tape dir — the OFFLINE namespace, no recall side-effect, the `.online`/`.recalling` bookkeeping roots never leak. **exec**: `$BRIX_FRM_STAGECMD dread <key> ''` with stdout captured (one name per line, trailing `/` = directory); a recall-only stagecmd that doesn't know the verb exits nonzero and stays not-enumerable. GOTCHA (burn in): a worker's spawned child is reaped by NGINX'S SIGCHLD handler — `exec_run` wins that race by waiting immediately, but draining the dread pipe to EOF loses it deterministically, so `exec_list` treats `waitpid`⇒ECHILD as reaped-elsewhere-success (output already collected; the contract prints entries only on success). `tests/test_frm_dirlist.py` (stub tape listing over live kXR_dirlist incl. subdir + no-recall + no-bookkeeping-leak; missing dir ⇒ kXR_error; exec dread via a shell-script stagecmd — needs nginx `env BRIX_FRM_STAGECMD=...;` since workers get a scrubbed environment). **rcreate (landed, wave 36):** the adapter vtable's `mkpath` verb (stub: mkdir -p under the tape root; exec: `<stagecmd> rcreate <key> ''` via `exec_run`'s immediate waitpid, which wins the SIGCHLD reap race) behind a new `sd_frm .mkdir` slot; kXR_mkdir on a tape export needed TWO gates opened — `BRIX_SD_CAP_DIRS_WRITE` in the driver caps (phase-71: CAP_DIRS lists, DIRS_WRITE mutates — missing ⇒ uniform EPERM before any dispatch) and `brix_allow_write on` (INVARIANT 3, the export was read-only). Tests now 5: + stub rcreate (dir lands on the tape root and lists afterwards) + exec rcreate (marker file proves the stagecmd received verb+key) |
| 8 | Scan engine walks raw POSIX, not the SD seam — frm_admin-audit parity broken for non-POSIX backends; `BRIX_SD_CAP_CATALOG` exists but unused by scan | PARTIAL | documented architecture gap |
| 9 | ~~`oss.maxsize` create-size cap~~ | **LANDED 2026-08-10** (parity-fix wave 7) | `brix_oss_maxsize <size>`: a shared `brix_write_within_maxsize` helper refuses a data write whose end offset (offset+len) crosses the cap with kXR_overQuota, wired into all three native write handlers (`write.c`/`pgwrite.c`/`writev.c` — pgwrite checks the decoded plaintext length; writev checks every segment before writing any, so a partial vector can't leak past the limit). Load-bearing at the write plane, not just the oss.asize open hint. Default 0 = uncapped. `tests/test_oss_maxsize.py` (raw-wire boundary + kXR_overQuota + xrdcp integration + writev-crossing security-neg) |
| 10 | Per-subtree path attributes (nomig/mkeep/nocheck/inplace/rcreate, attribute inheritance engine) | MISSING | attrs attach to export/tier only |
| 11 | Serving stored per-4KiB page CRCs for pgRead (CSI granule is 1MiB, edge blocks verified by scrub not hot path; wire CRCs computed at edge) | PARTIAL-BY-DESIGN | divergence documented in csi_tagstore.h |
| 12 | stagemsg/StageEvents external notification file | MISSING | in-band waiter + ledger substitute |
| 13 | oss.statlib stat-info seam (GPFS etc.) | MISSING | drivers stat directly |
| 14 | ~~Sizes-only synthetic backend (Mirage's zero-storage pattern reads)~~ | **LANDED 2026-08-10** | `brix_storage_backend mirage:<size>` — a full census-registered SD driver (`fs/backend/mirage/sd_mirage.c`, row in `core/types/fs_list.h`, conf contract in `sd_registry.h`, parse branch `vfs_backend_config.c`, build branch `vfs_backend_registry_source.c`): every path opens READ-ONLY as a regular file of `<size>` bytes whose content is the deterministic offset pattern `(o*131+7)&0xFF`, so any range read is independently verifiable — protocol/throughput testing with zero storage behind the export (the Mirage analog). No syscalls at all; caps `RANGE_READ` only (no fd ⇒ memory-served, the driver-backed read path handles fd-less objects); write-intent opens refused `EROFS`; `brix_export` still anchors the namespace (the block-backend pattern). `tests/test_mirage_backend.py` (pattern reads at 0/interior/EOF-straddle byte-exact over live root://, write-open refused + past-EOF empty, malformed size fails `nginx -t`); the census-map unit test `tests/test_fs_id_map.c` — previously ORPHANED (no surface ran it) — is now driven by `tests/test_fs_id_map.py` (standalone cc build per its own header, ngx-free) and pins the mirage row, the always-present anchors, and the append-only rule (posix stays row 0 — renumbering would re-key the per-backend SHM byte counters) |
| 15 | ~~OssStats `slowop` threshold classifier~~ + mid-op duration increments | PARTIAL (wave 16) | `brix_metrics_slowop <usec>` arms a latency threshold stamped into the metrics SHM at init_module; the lock-free latency record path books any op whose measured latency meets/exceeds it into `brix_io_slowop_total{proto,op}`, and the armed threshold is exported as `brix_io_slowop_threshold_usec` (0 = disabled, byte-identical to the pre-knob behaviour). `tests/test_metrics_slowop.py` (armed-1µs books / default-0 disabled / 1h-threshold not-booked trio, scraped off `/metrics`). Mid-op (in-flight) duration increments remain — the classifier books at completion, alongside the existing histogram. |
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
| 3 | Per-page origin verification for partial fills (pgRead net cschk) + ~~`uvkeep` (age-out never-verified entries)~~ **LANDED 2026-08-10** | PARTIAL (per-page verify still open) | slice fills trust TLS; best-effort commits unverified forever. **uvkeep**: `brix_cache_uvkeep <time>` (upstream pfc.uvkeep) — a COMPLETE cache entry whose contents were never checked against the origin digest (cinfo `F_VERIFIED` clear — a TLS-trusted fill with no checksum to compare) is treated as a MISS once older than `<time>` from its `filled_at`, so the next open revalidates it against the source. A verified entry, one still inside the window, or one with no recorded fill time serves normally — the knob only ADDS revalidation, never serves anything it would not already (fail-safe direction). One gate in `cache_open_serve_hit` (`fs/backend/cache/sd_cache.c`) after the F_COMPLETE check; wired through the shared cache policy (`brix_cache_policy_t.uvkeep`, tier-directive grammar so all protocols speak it, default 0 = off = today's behaviour). `tests/test_cache_uvkeep.py` (fill an UNVERIFIED entry, swap the source out from under it: inside the window the cache still serves its own copy — proving no auto-revalidation, which isolates uvkeep — then past the window the aged entry revalidates and the new bytes serve) + `tests/test_cache_directive_parse.py` (accept/reject/dup grammar). Divergence: BriX revalidation is a full refill (the miss path), stronger than a conditional HEAD |
| 4 | ~~`onlyifcached [minsize/minfrac]`~~ | **LANDED 2026-08-09** (minsize/minfrac not taken) | `brix_cache_only_if_cached on` (tier grammar, all protocols). In `sd_cache_open_common` a read MISS returns ENOENT → kXR_NotFound so the client fails over to another replica instead of making this node pull the object. Gated AFTER the hit test (a cached object still serves) and BEFORE the admission filter and the nearline/fill paths — otherwise an admission-declined path would still reach the source, the exact bypass the mode exists to prevent. Writes always pass through. The `minsize`/`minfrac` partial-hit thresholds are NOT implemented (a partial hit counts as a miss). |
| 5 | Serve-while-filling whole-file mode (background prefetcher, read queue-jumping, stop-on-close) — BriX whole-file fill is foreground, first reader waits | PARTIAL | slice mode covers latency case |
| 6 | ~~chmod + statfs/Stats forwarding on sd_xroot~~ | **LANDED 2026-08-10** (chmod wave 12, Qspace wave 13, QFSinfo wave 14) | **chmod**: sd_xroot grew `.setattr`/`.setattr_cred` slots forwarding `attr->set_mode` to the origin via `brix_cache_origin_chmod` (kXR_chmod by path, mode BE16); before this `brix_vfs_chmod` found a NULL slot and returned a SILENT no-op success. Times/owner stay a no-op (remote node owns its timestamps). **statfs**: BOTH capacity reports — kXR_Qspace (detailed oss.* bytes) and kXR_QFSinfo (the compact "wVal freeMB util" that CMS/kXR_locate reads for writable-server selection) — reported the LOCAL export's statvfs even for a backend whose capacity lives elsewhere. Both now share one `query_space_probe`: the dormant `brix_vfs_space` seam (implemented by pblock, never called) is consulted first, so a pblock export reports its quota and an sd_xroot proxy forwards the query to the origin (new `.space` slot → `brix_cache_origin_space`); a plain POSIX export declines and falls back to statvfs unchanged. Sharing one probe means Qspace and QFSinfo can never disagree about which store a proxy advertises. `tests/test_cmd_xroot_gateway_regress.py` (`_check_chmod`) + `tests/test_qspace_driver.py` (pblock-quota seam / proxy-forward / posix-fallback trio, each asserting BOTH Qspace and QFSinfo) |
| 7 | ~~File-usage (cached-bytes-owned) watermarks distinct from FS occupancy (`diskusage files`)~~ | **LANDED 2026-08-10** | `brix_cache_max_bytes <size>` caps the cache's OWN total bytes, a second reaper arm independent of the ppm FS-occupancy watermark: on a shared filesystem statvfs reflects everyone's data, so the FS mark either never fires (huge mount) or thrashes (a noisy neighbour) — the cap bounds the cache by what IT holds. The watermark reaper (`reap_watermark.c`) grew a `files_wm_on` arm that, under the same cross-worker lock, runs `brix_cache_purge_to_max_bytes`: sum the candidate set's sizes and, if over the cap, evict oldest-first (tracking owned − evicted_bytes) until back within it. Reuses the ppm engine's candidate collection + `brix_cache_evict_one` primitive (both hoisted to `evict_internal.h`, with a `skip_usage_remeasure` flag so the bytes purge skips the per-unlink statvfs the ppm passes need), so a victim is cold-tier-demoted / manager-unregistered / sidecar-cleaned identically. Default 0 = off; the reaper timer now arms on EITHER a valid FS watermark OR max_bytes > 0. `tests/test_cache_max_bytes.py` (fill 512 KiB past a 256 KiB cap, reaper brings the on-disk footprint back to the cap without emptying it) + `tests/test_cache_directive_parse.py` (accept/reject/dup). Divergence: BriX counts data objects + their tiny cinfo/meta sidecars as owned bytes (a small over-count, evicts marginally sooner); stock counts data only. Evicts DOWN to the cap (the 1 s..60 s reaper cadence rate-limits re-eviction, no separate low-mark) |
| 8 | Per-directory stats/quota tree (dirstats/DirState/ResourceMonitor/purge-pin) | MISSING | global counters only |
| 9 | Direct cache access (`pss.dca` redirect-to-local-path) | MISSING | largely obviated by sendfile; manager re-registration is the cousin |
| 10 | Forwarding-proxy mode (client-named origin URL + protocol allowlist) | MISSING | security-sensitive; reuse TPC egress-verdict core |
| 11 | ~~Admin evict/fevict verb~~ | **LANDED 2026-08-10** (parity-fix wave 5) | Stock `xrdfs cache {evict\|fevict} <path>` travels as kXR_set "cache <verb> <path>" (pinned live via XRD_LOGLEVEL=Dump against 5.6.9); the set handler now recognizes both spellings, gates them like a delete (allow_write FIRST — invariant 3, enforced in-handler since kXR_set skips the write-plane gate — then BRIX_AUTH_DELETE + token scope on the CONFINED path), and drops the cached copy through `brix_sd_cache_evict`. Idempotent on an uncached path; kXR_Unsupported without a cache tier; evict==fevict (no in-use refusal — documented divergence). BriX xrdfs grew the matching `cache` verb (`brix_set_cmd`). `tests/test_cache_evict_cmd.py` (4 cases incl. a STOCK-client fevict drop-in proof and the read-only + `..` security-negs) |
| 12 | RAM budget/writequeue for fills; RAM-only cache tier (XrdRmc) | MISSING / N-A-leaning | OS page cache substitutes for serving |
| 13 | Per-open CGI blocksize/prefetch override (`pfc.urlcgi`) | MISSING (likely deliberate under opaque_strict) | |
| 14 | pss.permit host ACL, pss.persona mapped identity (BriX forwards REAL identity instead — arguably better), pss.reproxy, root:// origin connection pool (per-fill bootstrap today) | MISSING/low | pool matters only if origin-open latency shows up |
| 15 | cinfo per-access history ring (`acchistorysize`) + ~~cinfo self-CRC~~ (STALE — verified done, wave 38) | PARTIAL (ring only) | ~~bit-flip in well-formed cinfo undetected~~ — FALSE for the current tree: this row predates cinfo's move onto the shared xmeta carrier (`fs/meta/`, reached via `brix_xmeta_path_load/save` — `fs/cache/cinfo.c:203-219`), whose record format IS self-CRC'd throughout: the stock-compatible region (`version + Store POD + crc + bitmap + AStat[] + crc`, matching stock's own Store/bitmap checksum — `xmeta_encode.c`) and every BriX extension section (`{type, len, payload, crc32c}` TLVs; a bad section crc rejects the section). A flipped bit anywhere in a well-formed record makes load return ERR (torn record ⇒ treated as absent, refilled — never served). PROOF: `src/fs/meta/xmeta_unittest.c::test_corruption` flips a byte in each guarded region (store POD / bitmap / section payload) and asserts decode rejects, then restores and asserts it decodes again — verified green 2026-08-10 (driven by `tests/cmdscripts/metadata_live_ports.py`). Only the per-access history ring remains open (BriX keeps ONE aggregate AStat — a ring is a hot-path change of marginal value, assessed wave 18) |

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
| 9 | ztn `-expiry ignore/optional` (BriX = required only); ~~`-maxsz` knob~~ **LANDED 2026-08-10** (parity-fix wave 6) | PARTIAL (expiry modes still deliberately stricter) | `brix_ztn_maxsz <size>`: refuse an over-long bearer credential BEFORE any parse/JWKS/crypto work (unauthenticated peers must not choose the validation CPU burn); default 0 = uncapped, byte-identical to the pre-knob behaviour. `tests/test_ztn_maxsz.py` (gate fires / gate scoped / default-uncapped trio distinguishing the size refusal from the validation refusal by error text) |
| 10 | xrd.tlsca residuals: crlcheck last-scope, ~~verdepth for stream listener~~ (LANDED wave 17), verification-log toggle; ~~xrootd.tlsreuse~~ (LANDED wave 19); ~~xrd.tlsciphers for stream listener~~ (LANDED wave 18) | PARTIAL/MISSING | **verdepth**: `brix_gsi_verify_depth <n>` caps the accepted X.509 chain depth when verifying a client's GSI proxy/cert at root:// login — `brix_gsi_verify_chain` already honoured a depth arg (→ `X509_STORE_CTX_set_depth`), but the root:// caller passed a hardcoded 0 (unlimited); now it passes `conf->gsi_verify_depth` (default 0 = unlimited, unchanged). `tests/test_c_auth_units.py::test_c_auth_unit[gsi_verdepth]` (deep forged chain: uncapped-accept / depth-1-reject / depth-20-accept, against the real verify fn) + `tests/test_gsi_verify_depth.py` (wiring + directive parse/validate). **tlsciphers**: `brix_tls_ciphers <list>` pins the TLSv1.2-and-below cipher list (`SSL_CTX_set_cipher_list`, same scope as nginx `ssl_ciphers`) and `brix_tls_ciphersuites <list>` (wave 20) pins the TLSv1.3 suites (`SSL_CTX_set_ciphersuites`) on the root:// in-protocol TLS context — both in `brix_configure_tls`; TLSv1.3 is today's default protocol, so the suites knob is what actually restricts a modern connection. An unmatched list on either is a hard config error (never a silent default fallback). `tests/test_tls_ciphers.py` (valid-pinned / unmatched-rejected / default-unchanged, via `nginx -t` accept-reject which runs the real config-init cipher application). **tlsreuse**: `brix_tls_reuse on\|off` — off disables the root:// TLS session cache + tickets (full handshake per connection) via the header-inline `brix_tls_apply_session_reuse` (`tls_session.h`); default on = unchanged. `tests/test_c_auth_units.py::test_c_auth_unit[tls_reuse]` (self-contained OpenSSL unit: off-disables cache+NO_TICKET / on-inert / null-safe) + `tests/test_tls_reuse.py` (wiring + config-init off-branch/default). crlcheck last-scope and verification-log toggle remain; nginx covers the HTTP side. |
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
| 2 | ~~**HTTP-TPC checksum verification**~~ | **LANDED 2026-08-05** (this row was stale — §9.1.11 already recorded it) | `webdav/tpc_verify.c`: post-pull completion gate on every pull tier (sync/thread/marker + the curl_multi multi-stream driver) — one HEAD re-probe carrying Want-Digest, Content-Length vs bytes-on-disk, RFC-3230 Digest recomputed over the staged temp. Fail-closed when enabled (missing/unparseable/uncomputable Digest or mismatch ⇒ 502, temp aborted, never committed); both halves off by default. `brix_webdav_tpc_require_source_size` / `brix_webdav_tpc_verify_checksum <alg>` deliberately mirror the native pair (`brix_tpc_require_source_size`/`_verify_checksum`, `src/tpc/outbound/source_stream.c`). Tests: `tests/test_webdav_tpc_completion_gate.py`, `tests/test_tpc_pull_integrity.py` |
| 3 | ~~**TPC push skips Layer-2 egress allowlist** (pull enforces)~~ | **ALREADY FIXED 2026-08-04** (this row was stale) | The push branch of `ngx_http_brix_webdav_tpc_handle_copy` runs `webdav_tpc_source_guard()` on the `Destination` authority before `webdav_tpc_handle_push()` — same verdict core, same 403, same `signal=tpc_egress` line as a pull (`webdav/tpc.c:347-363`). Covered by `tests/test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse` (4 cases). See testsuite-combinatorial-coverage-audit-2026-08-04.md §2.2. |
| 4 | ~~Want-Digest q-value/multi-algorithm negotiation (first token only)~~ | **LANDED 2026-08-09** (parity-fix wave 2) | `xrdhttp_select_rfc3230_algo` (webdav/xrdhttp.c): full comma-list walk, RFC 7231 q-values in thousandths (absent → 1.0), highest-q algorithm this build supports wins (ties keep list order); an acceptable-but-unsupported list falls back to the historical first-token path (downstream refusal unchanged); an all-q=0 list computes NOTHING — the client explicitly refused every algorithm. 3 new cases in `tests/test_xrdhttp_wait_retry_digest_range.py` |
| 5 | `http.header2cgi` arbitrary header→CGI bridge | MISSING | |
| 6 | ~~HTML directory listing on GET + listingdeny/listingredir~~ | **LANDED 2026-08-10** (parity-fix wave 8) | `brix_webdav_html_listing on` renders an escaped HTML index (name/size/mtime) on a directory GET from the SAME impersonation-aware VFS opendir/readdir seam PROPFIND uses — dotfiles + internal sidecars hidden, every name run through the shared XML escaper (no injection). `brix_webdav_listing_redirect <url>` is the listingredir analog (301 to `<url><request-uri>`, checked first); neither directive = the stock listingdeny default (403). Wired at the GET orchestrator: the open-and-stat helper stays side-effect-free (signals directory via NGX_DECLINED) and `get_serve_directory` owns the response. `tests/test_webdav_html_listing.py` (4 cases incl. an escape/hide security-neg) |
| 7 | ofs.tpc identity matrix: `allow dn/group/host/vo`, `require {all|client|dest} <auth>`, `restrict <path>`, `oids` | MISSING | host-plane + global confinement substitute |
| 8 | Native TPC multi-stream (`ofs.tpc streams`) — single-stream 1MiB loop; push multi-stream also N/A | MISSING | HTTP pull has it |
| 9 | ~~`xfr <n>` explicit concurrency cap~~ (split client-TTL vs max TTL still implicit) | **LANDED 2026-08-10** (parity-fix wave 10) | `brix_webdav_tpc_xfr <n>`: `brix_tpc_registry_add` gained a `max_active` param — a new COPY beyond N in-flight transfers is refused (registry returns 0 → 503), tracking LIVE in-use slots (a reap runs first so an abandoned transfer never permanently counts). Wired into both WebDAV register paths (sync `tpc.c` + threaded `tpc_thread.c`); native root:// TPC passes 0 (unchanged, slot-ceiling only). Default 0 = no extra cap. `tests/c/test_tpc_xfr_cap.c` (cap/refuse/release/uncapped over the real SHM registry) |
| 10 | ~~Perf-marker `RemoteConnections:` line~~ | **LANDED 2026-08-10** (parity-fix wave 4) | Every multi-stream stripe's marker block now carries `RemoteConnections: tcp:<ip>:<port>` (IPv6 bracketed) — the CONNECTED endpoint from CURLINFO_PRIMARY_IP/PORT captured once on the stream's first write callback (write-release into the shared progress struct), never Source-URL text, so a hostile URL cannot be reflected into the marker stream; the single-stream tier omits the optional line rather than fabricating one. `tests/test_tpc_marker_remoteconn.py` (3 cases incl. a strict-endpoint security-neg). **Found en route (§9.2):** the marker tier was permanently DARK for `location{}`-scoped exports — its gate checked `common.thread_pool` directly, which only the server-scoped postconfig resolver fills; fixed by promoting the lazy pool lookup to the shared `brix_http_thread_pool()` |
| 11 | tpc.fixed_route; ~~http.maxdelay~~ **LANDED 2026-08-10**; selfhttps2http | PARTIAL (fixed_route/selfhttps2http still open) | **http.maxdelay**: `brix_webdav_maxdelay <time>` caps the `Retry-After` a 202 "staging" (nearline/tape recall) GET tells the client to wait — a hardcoded 10 s until now. It only ever TIGHTENS the poll cadence (a value ≥ 10 s is a no-op; 0 = off = the default 10 s), so a deployment that wants faster recall polling can get it without ever lengthening a client's back-off past what the server intends. One clamp at the 202 emission (`webdav/get.c`), default path byte-identical (static "10", the config read allocates only when actually tightening). `tests/test_webdav_maxdelay.py` (nginx -t accept/reject/dup — the 202 path itself needs a live nearline recall to fire, so the config grammar is what is guarded here; the clamp is a `min()` on an existing separately-covered emission). tpc.fixed_route (pin a TPC route) and selfhttps2http (loopback https→http downgrade) remain — both low value. |
| 12 | Dig over root:// plane (`/=/`) | PARTIAL | HTTP-only by design |
| 13 | One brix-HTTP protocol per port (webdav|s3|cvmfs exclusive) vs sharing | DIVERGENT | root+http handoff pairing exists |

---

## 7. Client stack (XrdCl / xrdcp / xrdfs / preload / FUSE / XrdEc / apps)

The repo's `docs/10-reference/xrootd-feature-matrix.md` "XrdCl" row (fixed
2026-08-09; it long read "No") now reflects reality —
`client/` is a full native client (sync + epoll/io_uring async cores, GSI/sss/pwd/
krb5/token auth incl. client-side GSI delegation round, pgread/pgwrite w/ pgRetry on
write, readv/writev, ZIP, TPC orchestration, capture/replay, resilient reopen-resume,
`~/.xrdrc` endpoint aliases). Machine-checked xrdfs parity gate exists
(`tests/test_clientconf_surface.py` live-parses stock XrdClFS.cc).

**Gaps (ranked):**

| # | Gap | Status | Notes |
|---|-----|--------|-------|
| 1 | ~~**Metalink** end-to-end~~ | **LANDED 2026-08-09** (phase-100) | v4+v3 parser + virtual-redirector failover + digest inheritance, all source transports; --tls-metalink / --zip-mtln-cksum deliberately not taken (phase-100 §3) |
| 2 | ~~**Extreme copy** (--sources, XCp block-stealing multi-replica)~~ | **LANDED 2026-08-09** (phase-100) | `--sources N` engine: metalink mirrors → locate → duplication; block stealing + dead-replica rescue; --dynamic-src not taken (needs known size). Join-gate hardening added later same day (§0 working-tree additions): open-resolution barrier + 1 s grace so a fast source cannot drain the block table before a slow sibling joins |
| 3 | **Sub-stream data fan-out**: kXR_bind done, pathid never stamped (`net/streams.c:9-14`) — `--streams` cosmetic; GSI-signed sessions also rejected by aio attach (no pipelining when signed) | PARTIAL | pairs with server §1 gap 1 |
| 4 | ~~**tried=/triedrc= never emitted** by BriX clients (server parses them!)~~ | **LANDED 2026-08-09** (dead-target failover; DS-error retry still open) | `frame_roundtrip.c`: when a redirect target is unreachable and the client falls back to the home manager, the replayed request carries `tried=<hostport>&triedrc=<reason>` with the stock reason tokens (enoent/ioerr/fserr/srverr). Emitted only for the opcodes BriX's own manager parses `tried=` for — open/stat/query (`open_manager.c`, `stat_manager.c`, `checksum_qcksum_path.c`) — so emission and consumption cannot drift, and never on a first attempt. NOT taken: retrying at the manager when a data server returns an ERROR (that is a behaviour change, not an emission gap). |
| 5 | ~~**`--tpc delegate` hardcodes `tpc.dlgon=0`** — silently degrades to `first`~~ | **LANDED 2026-08-09** | `tpc_build_dst_opaque` emits `tpc.dlgon=1` for `XRDC_TPC_DELEGATE`, 0 otherwise. The wire flag alone was not enough: the client also REFUSED the destination's kXGS_pxyreq round unless `$XRDC_GSI_DELEGATE` was set, and advertised no delegation capability, so a stock destination would never ask. `--tpc delegate` now sets `brix_opts.gsi_delegate`, which one predicate (`gsi_delegation_enabled`) drives for both the kOptsSigReq advertisement and the sigpxy round — advertise and honour can no longer disagree. |
| 6 | ~~**`--continue` byte-offset resume** — partials unlinked on failure; journal (`--journal/--resume`, EXTRA) is whole-file only~~ | **LANDED 2026-08-10** | `copy_continue.c` (new TU): --continue writes the destination IN PLACE and resumes at an existing partial's size over the resilient rfile pread path (reconnect+reopen mid-tail). The mode is the explicit opt-OUT of the temp+rename discipline: failed transfers keep the partial; a COMPLETED file failing --cksum is still dropped (fail-closed on integrity verdicts, only in-progress partials are protected). Local-larger-than-source refused; parse-time exclusive with -f/--pgrw/--compress/--zip*/--journal/--resume (a different resume system). Gate runs before the destination-exists refusal in `copy_download`. brix-xrdcp usage + xrdcp(1) updated. `tests/test_xrdcp_continue.py` (8 cases: partial→byte-exact resume, fresh/equal-size behavior, oversized-local refusal leaves bytes untouched, conflict matrix, poisoned-partial + --cksum removes the completed file) |
| 7 | ~~**fork-safety** — no pthread_atfork; forked child inherits aio fds → hang/SID collisions~~ | **LANDED 2026-08-10** | `net/forksafe.c`: a process-wide conn registry (brix_connect registers, brix_close unregisters first-thing) + pthread_atfork trio. The child handler NEUTERS every inherited conn: fd closed with no protocol goodbye (the worst pre-fix hazard was brix_close's fire-and-forget kXR_endsess killing the PARENT's session), TLS/--capture handles abandoned UNFLUSHED (flushing shared stdio buffers would duplicate the parent's bytes), conn marked `forked` → every op refuses with a NON-retryable verdict (so the resilient layer cannot silently re-login as the child). `brix_conn_usable()` lets long-lived embedders re-dial transparently — the preload shim now does, so a child's new opens just work while inherited handles fail cleanly. End-to-end fork test through the shim: `tests/test_client_forksafe.py` (child fresh-session success + inherited-handle clean failure + parent stream byte-exact to EOF after the child exits). aio-thread inheritance is moot (threads do not survive fork; the child never touches their fds thanks to the neuter) |
| 8 | **Preload**: ~~no write path~~ **LANDED 2026-08-10** (wave w): an `open(O_WRONLY[,O_CREAT/O_TRUNC/O_EXCL])` under the BRIX_VMP prefix now diverts to a resilient remote write handle (`remote_open_write` → `brix_rfile_open_write`), `write`/`pwrite` stream to the server, `close` commits; write-only shim fds refuse `read` (EBADF), and the create/overwrite/update tristate follows the open flags. LIMIT (documented, symmetric with the read path): the shadow fd is a fake number, so shell `>`/`<` redirection — which dup2's the fd — is not diverted; direct fd use (cp, a program opening+writing) is the contract. `tests/test_preload_write.py` (byte-exact cp upload, read-back, sequential-write, outside-prefix-untouched, write-only-not-readable). Still deliberately narrow: no readdir family, no stdio (fopen…), no statfs/chdir/xattr aliases; single conn + global mutex; BRIX_VMP single mapping. ~~`fill_stat` under-fills~~ FIXED 2026-08-09 (`tests/test_xrootdfs.py`). Shim core split for the 600-line gate: `brixposix_preload.c` (open/read/write/close) + `brixposix_stat.c` (stat/access family) sharing state via `brixposix_internal.h`, whose cross-TU helpers are `visibility("hidden")` so the interposing `.so` never re-exports them into the host's symbol table. | PARTIAL (deliberately narrow) | |
| 9 | **xrootdfs**: no multi-data-server fan-out/dirent merge/nworkers (the defining XrdFfs feature), no CNS journal, no per-request sss uid/gid identity (all users collapse to mounting user), no ofsfwd, no SIGUSR1 refresh, no special xattrs; ~~mknod absent~~ **LANDED 2026-08-10**: `.mknod` now creates an empty regular file (`xfs_mknod`, `client/apps/fs/xrootdfs_io.c` — create-new write handle → flush+close, force=0 so an existing path gives EEXIST; a non-regular type FIFO/dev/socket is refused EPERM, never silently made a plain file; WebDAV mount → EROFS); the `mknod(2)`/`mknodat(2)` syscall path used to return ENOSYS. `tests/test_xrootdfs.py` (empty-file-lands-on-server, mknod-then-write, FIFO→EPERM security-neg). usage text stale (utimens/chown/symlink ARE implemented) | PARTIAL | extras: WebDAV backend, resume, readahead/writeback, stable inodes |
| 10 | ~~**Zero `XRD_*` env compatibility** (~40 stock keys silently ignored; own XRDC_* namespace) — drop-in hazard~~ | **CLOSED 2026-08-10** (aliases + loud ignore) | Two mechanisms: (a) the stock timeout spellings are honored as seconds-scaled aliases of the native ms knobs — `XRD_CONNECTIONWINDOW`→connect, `XRD_REQUESTTIMEOUT`→io, `XRD_STREAMTIMEOUT`→stall (`nettmo.c`; native `XRDC_*` always wins, divergence noted once, overflow clamps to INT_MAX never wraps); (b) every OTHER set `XRD_*` variable triggers ONE TTY-gated note naming it (`envalias.c` `brix_env_warn_stock_unsupported`, called at first `brix_connect`; scripts keep byte-identical output per the C3 hint gate — names only, never values). Remaining stock keys stay deliberately unmapped: they tune subsystems BriX spells differently (`--streams`, `--retry`, xrdrc) and now say so out loud. brix-env(7) documents the mapping. `tests/test_client_env_compat.py` (6 cases: tarpit-bounded bring-up, native precedence, overflow clamp, garbage fall-through, TTY note, no-TTY silence) |
| 11 | Redirect collapse / VirtualRedirector registry client-side (also the metalink hook); async engine doesn't follow redirects itself | MISSING/PARTIAL | |
| 12 | xrdfs residuals: ~~multi-path stat/rm/cat act on LAST path only~~ (FIXED, §9.2); ~~`stat -q` flags~~ + ~~locate flags (options=0 hardcoded) + deep-locate~~ **LANDED 2026-08-09** (parity-fix wave 3): `stat -q` with the stock vocabulary and '&'=all / '|'=any semantics + exit codes 0/55/50 pinned LIVE against stock xrdfs 5.6.9; `locate [-n] [-r] [-d] [-m|-h] [-i] [-p]` — -r/-n/-m set the kXR_refresh/kXR_nowait/kXR_prefname wire bits (new `brix_locate_opts`), -i/-p hold by default (no name resolution, no tried= on first attempt), -d deep-locates every file via the shared walk (`tests/test_xrdfs_locate_statq.py`, 8 cases). ~~prepare -p/-a~~ **LANDED 2026-08-10** (parity-fix wave 4): `-p <0-3>` priority + `-a` abort, wire-verified from the client's own `--capture` bundle — and the audit exposed WORSE: `-c` was mapped to kXR_cancel while stock `-c` means CO-LOCATE, so a stock script asking to co-locate silently ABORTED its stage; `-c` now sends kXR_coloc (`tests/test_xrdfs_prepare_flags.py`, 5 cases incl. the -c≠cancel security-neg). ~~cache evict/fevict verb~~ **LANDED 2026-08-10** (parity-fix wave 5, see §4.11 — `do_cache` + `brix_set_cmd`, stock-wire kXR_set transport). ~~`ls -u/-D/-Z/-C`~~ **LANDED 2026-08-10** (parity-fix wave 6): -u prints URL-formed entries, -C checksums every non-directory entry (kXR_Qcksum per file, "adler32:hex" column, per-entry failures inline — never aborting the listing), -Z lists a remote ZIP's members through the shared bounds-checked central-directory parser (random reads over a resilient rfile, no extraction; malformed EOCD refused cleanly), -D accepted as identity (single-server listings are never merged, so no duplicates exist to re-show) — 5 new cases in `tests/test_xrdfs_locate_statq.py` incl. a crafted-EOCD security-neg. ~~query 5/9 codes missing~~ **LANDED 2026-08-10** (wave l+1): `query` now speaks all nine stock spellings — checksumcancel (kXR_Qckscan cancel grammar), xattr, prepare (kXR_QPrep by request id), opaque, opaquefile joined config/space/checksum/stats, with the same cwd path-resolution rules (`tests/test_xrdfs_query_codes.py`, 5 cases incl. a traversal security-neg). ~~spaceinfo not drop-in (aliased df)~~ **LANDED 2026-08-10** (wave p): new `spaceinfo` verb emits stock 5.6.9's exact five-line report (Path/Total/Free/Used/Largest free chunk, labels padded to col 21, numbers from kXR_Qspace's oss.* keys — `tests/test_xrdcp_xattr_spaceinfo.py::TestSpaceinfo`). Documented divergence: BriX Qspace is whole-export, so spaceinfo on a missing subpath prints the export numbers where stock 404s. ~~REPL thin~~ **IMPROVED 2026-08-10** (wave t): the interactive shell now skips `#` comment + blank lines (a comment used to trip "unknown command '#'") and gates the `[host:port cwd >` prompt on an stdin TTY, so a piped command script yields CLEAN stdout — stock xrdfs script conventions (`tests/test_xrdfs_repl_script.py`, incl. a pty case proving the interactive prompt is preserved). ~~xattr grammar incompatible~~ **LANDED 2026-08-10** (wave u): the STOCK spelling `xattr <path> <set|get|del|list> <params>` (set takes name=value) is now accepted as a drop-in alias of BriX's `xattr <code> <path> ...` — a stock-form call used to be silently mis-read as a bare list; disambiguated by the first token (a BriX subcommand keeps BriX semantics, else a path+stock-code is the stock form). Stock grammar captured live from `xrdfs --help`. `client/apps/fs/xrdfs_xattr.c` (split from xrdfs_attr.c for the 600-line gate); `tests/test_xrdfs_xattr_grammar.py` (5: stock round-trip, both-grammars-read-same-attr, BriX regression, bare-path list, set-without-= usage error) | PARTIAL | 37 verbs + 19 EXTRAS otherwise |
| 13 | xrdcp residuals: cksum on TPC/web paths; ~~--xattr~~ **LANDED 2026-08-10** (wave p): -F/--xattr preserves USER-namespace extended attributes across a root://<->local copy over the kXR_fattr plane (best-effort — a failed attribute warns, the copy stays successful), with a hard namespace wall: system./security./trusted. names never cross in EITHER direction, so a hostile remote attribute name (e.g. security.capability) cannot plant kernel metadata on a local file (`client/lib/xfer/copy_xattr.c`, `tests/test_xrdcp_xattr_spaceinfo.py::TestXattrPreserve` incl. the hostile-namespace security-neg); ~~--coerce~~ **LANDED 2026-08-10**: -F/--coerce rides kXR_force (0x0004) on remote destination opens (wire-verified from the client's own --capture bundle; absent without the flag) — BriX servers have no mandatory usage-locking to override and accept the bit, stock destinations that enforce usage rules honor it; ~~--retry-policy~~ **LANDED 2026-08-10**: `force|continue` per stock — `continue` arms the §7.6 byte-offset engine so every attempt writes in place and each retry RESUMES (differential sever-shim test proves the retry connection moves less than the file, vs `force` refetching from zero; resume granularity = 1 MiB chunks so at most one in-flight chunk refetches); ~~-p/--path~~ **ROW CORRECTED 2026-08-10**: stock 5.6.9 has NO -p/--path flag (verified from live --help) — the row was audit folklore. **NEW documented divergence:** stock `--parallel <n>` means "N files at once" (BriX's --jobs) while BriX --parallel is the striped single-file download — a drop-in script saying --parallel 4 gets a usage error (value refused), never silent misbehavior; ~~--xrate(+threshold)~~ **LANDED 2026-08-10**: -X/--xrate paces the serial pump (token-clocked sleeps, ~250 ms read slices; parse-time exclusive with --parallel/--sources which bypass the pump; --continue's tail loop is paced too) and --xrate-threshold fails a transfer whose average rate sinks below the floor after a 3 s grace (`tests/test_xrdcp_xrate_cksum.py`); ~~sha-family cksums~~ **LANDED 2026-08-10**: sha1/sha256/sha512 compute locally (shared EVP kernel grew SHA-512) for :print and literal modes — sha*:source is a LOUD usage error naming the literal spelling, because the server checksum plane has no sha and the old outcome would have been a silent UNVERIFIED pass; ~~--rm-bad-cksum~~ **LANDED 2026-08-10** as an accepted alias of BriX's stricter fail-closed default (mismatched destinations are ALWAYS dropped — documented divergence); ZIP surface divergent (CGI ?xrdcl.unzip= vs --zip flag; BriX --zip means store-into-archive); ~~several stock spellings rejected (--parallel/--force/--recursive/--nopbar)~~ spellings **LANDED 2026-08-09** (--parallel existed; --force/--recursive/--nopbar/--silent added as aliases, `tests/test_xrdcp_transport_opts.py::TestStockLongSpellings`) | PARTIAL | extras: --sync/--delete/--exclude/--jobs/journal |  <!-- client-flags-allow: the row IS the list of stock flags BriX does not implement -->
| 14 | ~~pgread client per-page re-request on CRC mismatch (hard error today; write side has pgRetry)~~ | **LANDED 2026-08-10** | `ops_file_pg.c`: pages decode via the collect decoder (corrupt pages recorded, not fatal); once the response is drained each bad page is re-REQUESTED as a fresh 1-page kXR_pgread carrying the §1.2 ClientPgReadReqArgs {pathid 0, kXR_pgRetry} — tolerated by stock and BriX servers alike. Bounded: 2 attempts per page, ≤16 corrupt pages per request (beyond that the stream is refused as poisoned — no retry storm); a page that stays bad is the old hard error. `tests/test_pgread_client_retry.py` (deterministic MITM bit-flip shim: single-flip heals byte-exact [verified to fail with retries disabled], persistent corruption fails CLOSED with no destination file, 17-page flood refused outright) |
| 15 | ~~readv single fhandle per request (stock: per-segment)~~ | **LANDED 2026-08-10** | Oracle (stock XProtocol.hh): `struct readahead_list { fhandle[4]; rlen; offset; }` — each segment names its own handle, so one kXR_readv scatter-gathers across multiple open files. The BriX SERVER already supported this (§1); only the client sent a single fhandle. New `brix_file_readv_multi(c, files[], segs, nseg)` (per-segment handle; the existing single-file `brix_file_readv` is untouched — zero regression) + the `xrdfs readvm <path off len>...` verb (opens each path once with dedup, one readv across all). `client/lib/protocols/root/ops_file_rw.c`, `client/apps/fs/xrdfs_data_xfer_vec.c`; `tests/test_xrdfs_readv_multi.py` (interleaved two-file reassembly, handle dedup, single-file regression, missing-file clean error) |
| 16 | Declarative ops DSL (XrdClOperations) | MISSING | |
| 17 | ~~file:// transparent local handler (`brix_connect` rejects non-root://; VFS facade exists but callers must branch)~~ | **LANDED 2026-08-10** | The gap was not the scheme parse (net/url.c already maps file:// → local) but the COPY DIRECTION: brix_copy rejected every local→local pair outright. New `client/lib/xfer/copy_l2l.c` (`brix_copy_local_to_local`) handles file://↔local, bare local→local, and the `-` stdio endpoints on either side, reusing the transfer pump — file source via the VFS (size-bounded), stdin EOF-driven; file dest atomic temp+rename honoring -f, stdout raw. --xrate pacing rides the pump; --cksum runs post-commit (literal/print; :source is a no-op with no server). Self-copy (`-f X X`) is safe (temp+rename reads the original inode). `tests/test_xrdcp_local_to_local.py` (8 fleet-free cases incl. wrong-cksum-drops-dest and the self-copy security-neg) |
| 18 | ~~kXR_attn actions beyond asynresp (asyncrd/wt/go/di/ab/ms) ignored~~ | **LANDED 2026-08-10** | Oracle check (stock `/usr/include/xrootd/XProtocol/XProtocol.hh`): asyncab/di/rd/wt/av/unav/go are all marked **"No longer supported"** — only **asyncms** and **asynresp** are live in the 5.6.9 baseline. asynresp already has its waitresp path; the real gap was the unsolicited **asyncms** (server-push text message, outer streamid {0,0}), which `brix_recv` fell through to the "unexpected status" default on — FAILING the in-flight operation. Now `brix_recv` loops: an attn frame is surfaced (`recv_handle_attn` — actnum-gated, message filtered to printable ASCII so server text can't inject terminal escapes) and the real reply is still read. `client/lib/protocols/root/frame.c`; MITM-injection test `tests/test_client_asyncms.py` (op-survives-and-surfaces + control-byte-strip security-neg), fail-verified with the attn skip disabled |
| 19 | Connection multiplexing: no global URL→channel registry/PostMaster (explicit per-callsite pools); no StreamErrorWindow cross-op endpoint memory | PARTIAL | |
| 20 | Apps: xrdpwdadmin MISSING; cconfig MISSING (nginx `-T`/`-t` covers config dump/validate); xrdacctest-as-CLI MISSING (server engine exists; diag_authsuite is different); ~~xrdcks local xattr tool MISSING~~ **LANDED 2026-08-10** (wave v): `xrdcks <path> <cksname> [<cksval>|delete]` manages the `user.XrdCks.<algo>` xattr as the byte-exact 96-byte XrdCksData record (Name[16] fmTime[8 BE] csTime[4 BE] Rsvd[3] Length[1] Value[64], verified against stock XrdCksData.hh) — get prints/computes-on-miss, set stores a hex value, delete removes. Implemented CORRECTLY to the FORMAT, deliberately NOT bug-compatible with the stock CLI which on this build segfaults on get and drops the leading value byte on set. New `client/apps/cksum/xrdcks_xattr.c` (xrdcksum multi-call personality); `tests/test_xrdcks_xattr.py` (6, fleet-free, incl. a decode-the-record format check and a cross-check vs xrdadler32). Also verified drop-in: BriX xrdadler32/xrdcrc32c match stock output byte-for-byte. xrdreplay/RecordPlugin ≈ wire-level capture/replay only (no op-level CSV, timing, verify modes); xrdmapc/xrdqstats/xrdprep PARTIAL (flag subsets); wait41 semantics divergent (name collision); crc32c flags subset | MISSING/PARTIAL | EXTRAS: xrdckverify, xrdcinfo, xrdcksum manifests, xrdstorascan, fault-proxy, xrddiag doctor (~25 TUs), brixMount family |

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
Cache-fill paths are un-throttled. (The `source-verified-xrootd-comparison.md`
throttle row has since been corrected to "Partial / nginx+" — see §9.3.)

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
6. ~~Cache prefetch (§4.1)~~ **LANDED 2026-08-05**; ~~cold-file age purge
   (§4.2)~~ + ~~onlyifcached (§4.4)~~ **LANDED 2026-08-09**. Cache residuals
   still open: per-page origin verification + uvkeep (§4.3),
   serve-while-filling whole-file mode (§4.5), RAM tier (§4.12).
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
    fork-safety (§7.7); ~~XRD_* env compat (§7.10)~~ **CLOSED 2026-08-10**
    (timeout aliases + loud ignore, `tests/test_client_env_compat.py`);
    ~~tried= emission (§7.4)~~ landed 2026-08-09.
13. RAM cache tier (XrdRmc/memfile) (§3.6/§4.12).
14. SSI client lib + ShMap (§8); BWM queueing/flows; throttle.data/iops pacing.
15. Long tail: VOMS mapfile, SciTokens rule mapfile, sss v2 entity/ID registry,
    pwd admin/auto-reg, header2cgi, ofs.tpc identity matrix,
    fsoverload, Qconfig keys, admin socket. (fxhold TTL knobs,
    cms.dfs, cms.perf pgm, altds, blacklist patterns/whitelist/redirect,
    error constants landed 2026-08-09; HTML listings, QStats XML, oss.maxsize,
    ztn -maxsz, cache evict, ofs.maxdelay, chkpnt maxsz landed 2026-08-10.)

### 9.2 Verified bugs / dead code found during this audit
- ~~TPC push skips Layer-2 egress allowlist (pull enforces)~~ **ALREADY FIXED 2026-08-04** — this row was stale when written; the push branch guards the `Destination` authority (`webdav/tpc.c:347-363`) and `test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse` covers it. See testsuite-combinatorial-coverage-audit-2026-08-04.md §2.2.
- ~~`xrdhttp_send_redirect` implemented, zero call sites (dormant HTTP redirects).~~ **REMOVED 2026-08-05** (phase-95 W1), then **RE-IMPLEMENTED FROM A REAL CALL SITE 2026-08-09** (§6.1) — `webdav/redirect.c` selects the data server from the CMS registry (`brix_srv_select`) and signs the identity into the redirect CGI (`brix_http_secretkey`); no dormant scaffolding, wired into `webdav/dispatch.c` + the access-phase auth gate.
- ~~`--tpc delegate` hardcodes `tpc.dlgon=0` (silent downgrade)~~ **FIXED 2026-08-09** — dlgon now tracks the mode, and the client arms its own delegation (advertise + honour behind one predicate) so the mode works end-to-end rather than only on the wire.
- ~~xrdfs multi-path stat/rm/cat silently act on last path only~~ **FIXED
  2026-08-09** (parity-fix wave): every non-flag operand is now processed
  independently, POSIX-style — a failing path is reported and the remaining
  operands still run; exit code = first failure's; the `rm -r /` export-root
  refusal holds per-operand. `tests/test_xrdfs_multipath.py` (8 cases).
- ~~Throttle: `max_active_connections` parsed-never-enforced; IO-load + userconfig engines have zero call sites~~ **REMOVED 2026-08-05** (phase-95 W2, deletion variant) — the `brix_throttle_max_active_connections` directive, the `brix_throttle_userconfig_*` INI matcher, the `brix_throttle_charge_io`/`ioload_over` load metric and the `io_time_us`/`io_window` SHM node fields are all gone. `max_open_files` is the one throttle engine with an admission point and it stays. `brix_resv_status` KEPT deliberately: it has no product caller but it is the observation point for `tests/c/test_reservation.c`, which covers the live `brix_resv_schedule`/`done` engine — deleting it would trade dead code for lost coverage.
- ~~Preload `fill_stat()` duplicates and under-fills vs `posix_map.c:17` helper (no st_ino/blksize/blocks)~~ **FIXED 2026-08-09** (parity-fix wave): `fill_stat` now delegates to the shared `brix_statinfo_to_stat`, and the `statx` interposer (the path modern coreutils actually hit) maps through the same helper — stable nonzero inode (STATX_INO answered), 1 MiB blksize hint, 512-byte blocks. Three new preload tests in `tests/test_xrootdfs.py` incl. an outside-prefix passthrough security-neg. **Found while testing:** the preload `.so` links the lib's `.pic.o` set and a stale mixed-ABI `.so` SIGSEGV'd in `brix_capture_frame` during login. Root cause (**FIXED 2026-08-09**, superseding the earlier rm-the-`.so` workaround): the client Makefile's `DEPS`/`ALL_OBJS` never included the `.pic.d` dependency files, so `.pic.o` objects were rebuilt ONLY when their own `.c` changed — a struct-layout change in a header left every untouched TU's `.pic.o` at the OLD layout, and `libbrix.so`/`libbrixposix_preload.so` linked a mix of vintages (relinking alone cannot fix that; the OBJECTS were stale — a full PIC rebuild with identical flags eliminated the crash). `ALL_OBJS` now carries `$(PIC_OBJS)` + the preload object, and a `touch lib/brix.h` probe rebuilds all dependent PIC objects.
- sss/ztn/krb5 sessions never signing-keyed (`signing_active=0`) — request-tamper protection absent off-GSI. **The SILENT half is fixed 2026-08-09** (`handshake/sigver.c`): the enforcement no longer short-circuits before its own check — it logs one WARN per session and, with `brix_signing_required on`, refuses. Actually keying sss/krb5 (both have key material; stock signs sss) remains open and is a wire change needing matched client+server derivation.
- **NEW 2026-08-09** — `cache_reap.c::reap_remove` logged every reap as a success without verifying it: a data file the cstore adapter failed to evict was counted+logged as reaped, then lost its `.cinfo` sidecar and looked untracked on every later pass, so it was never revisited. A leak that reported as success. Now verifies, falls back to `unlink`, and logs an error if the file survives.
- ~~`xrootdfs_usage.c:47-48` claims utimens/chown/symlink unsupported — they are implemented~~ **FIXED 2026-08-09** (parity-fix wave): the usage note now states the extension-gated reality (vendor kXR_setattr/link when advertised, ENOTSUP otherwise).
- **NEW 2026-08-10 — FIXED** (parity-fix wave 4): `xrdfs prepare -c` sent
  kXR_cancel where stock's `-c` means CO-LOCATE (stock's abort is `-a`, which
  BriX lacked entirely) — a stock script asking to co-locate a stage silently
  ABORTED it. `-c` now sends kXR_coloc, `-a` sends kXR_cancel, `-p <0-3>`
  carries the priority; wire-verified from the client's own `--capture`
  bundle (`tests/test_xrdfs_prepare_flags.py`). The redteam probes that used
  `-c`-as-cancel were moved to `-a`.
- **NEW 2026-08-10 — FIXED** (parity-fix wave 4): the HTTP-TPC 202 marker
  tier was permanently dark for `location{}`-scoped webdav exports — its gate
  checked `common.thread_pool` directly, but the postconfig resolver fills
  that pointer only when `brix_webdav on` sits at server{} scope, and every
  fleet/test config scopes it in a location. The lazy name-based lookup that
  `http_serve_offload.c` already used is now the exported
  `brix_http_thread_pool()` helper and the marker gate goes through it.
  Configs without a marker interval decline earlier, so no other tier's
  behavior changes.
- **NEW 2026-08-09** — S3 `brix_pmark*` registrations were dead code: the family
  was hand-copied into BOTH the webdav and s3 HTTP command tables, and nginx is
  first-module-wins with webdav preceding s3 in module order — so every
  `brix_pmark*` in any HTTP context wrote the *webdav* conf while the S3 request
  path read its own untouched conf. SciTags marking on S3 traffic was a silent
  no-op with no config-time diagnostic possible. **FIXED** (phase-101 W1, working
  tree): family registered once on `ngx_http_brix_common_module` at
  `BRIX_HTTP_ALL_CONF` scope (server{}/http{} placement now works, matching the
  stream plane), both protocol tables deleted, 13 config-time fields adopted via
  `brix_shared_adopt_unified()` (runtime tail deliberately never merged).
  `tests/test_pmark_s3.py`: firefly emission at location AND server scope,
  `brix_pmark_domain bogus` still fails `nginx -t`, pmark-off emits nothing.

### 9.3 Stale repo docs to fix
- ~~`docs/10-reference/xrootd-feature-matrix.md:67` — "XrdCl client library: No"
  row stale~~ **FIXED 2026-08-09** (parity-fix wave): row now reads "Yes
  (clean-room)" and summarizes the `client/` stack with a pointer to §7's
  residual gap list.
- ~~`source-verified-xrootd-comparison.md` — throttle "Parity/nginx+" optimistic
  vs source~~ **FIXED by 2026-08-09**: the row (at
  `docs/10-reference/source-verified-xrootd-comparison.md`) now reads
  "Partial / nginx+" and names exactly what phase-95 deleted and what remains
  unimplemented (throttle.data/iops pacing, loadshed, fairness).

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
