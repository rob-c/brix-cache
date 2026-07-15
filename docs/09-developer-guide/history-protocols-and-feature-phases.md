# Development History — Protocol Features & Data-Plane Phases

**Date:** 2026-07-15
**Status:** Living historical record — synthesizes ~50 session-memory entries
covering native XRootD/pgio, S3, WebDAV extras, CMS clustering, proxy mode,
pipelining, mirroring, dashboard, monitoring/AF-bridging, and federation work
from roughly phase-4 (2026-06-12) through phase-58+ (2026-07-04).
**Scope:** what shipped, in what order, the design decisions Rob made and why,
the concrete bugs found (root cause + fix, so they aren't reintroduced), the
gotchas that cost real time, and what's still open. This is the *protocol/
data-plane* companion to
[lessons-migration-era-2026.md](lessons-migration-era-2026.md) (structural
refactors) — read that one for build/migration mechanics, this one for
feature history.

**Related:** [lessons-migration-era-2026.md](lessons-migration-era-2026.md) ·
`docs/refactor/00-overview.md` (phase index) · the individual
`docs/refactor/phase-NN-*.md` docs cited inline below (this document does not
repeat their implementation detail — it captures the narrative, decisions, and
incidents around them).

---

## 0. How to read this document

Most phases below have a companion `docs/refactor/phase-NN-*.md` design doc —
this history does not re-derive their content. What follows is the material
that lives *only* in session memory: chronology, the "why" behind a design
choice, the bug that a phase actually found, and the gotcha that ate an hour.
Phase status is summarized in tables; narrative sections carry the lessons.

---

## 1. Chronological inventory

The module was largely protocol-*complete* by early June 2026 (phases 1–20s);
the work chronicled here is the second wave — closing wire-fidelity gaps
against stock XRootD, adding swiss-army features stock doesn't have, and then
a sustained performance-parity push. Rough timeline:

| Date | Phase / feature | Outcome |
|---|---|---|
| 2026-06-12 | Phase-4 op-descriptor audit, Phase-6 WebDAV helper consolidation, Phase-9 S3 SigV4, Phase-10 dashboard/jansson, Phase-12 shared file-serve, Phase-21 subrequests/filters | All reviewed and confirmed complete; several had dead code removed |
| 2026-06-12 | Phase-23 dynamic upstreams (admin REST API + SHM proxy pool), Phase-24 traffic mirroring, Phase-25 rate limiting | All landed, A–I/A–F scope, new `src/mirror/`, `src/ratelimit/` |
| 2026-06-12/13 | Phase-31 memory-budget streaming | W1/W3/W2.1 landed; found + fixed a pool-churn UAF that had been silently corrupting large reads |
| 2026-06-13 | Phase-13 write pipelining precursor: Phase-29 (read pipelining P1/P2/P4), Phase-30 (hyper-opt M0/M1), Phase-32 (data-plane perf WS1/2/4/5), Phase-33 (perf P2), Phase-25 W7 (stream concurrency) | Landed; kTLS measured as a *regression* on this hardware |
| 2026-06-14 | CRC64 (crc64/crc64nvme) across all surfaces; Phase-36 IPv6 completion | Both complete and verified |
| 2026-06-15 | Phase-39 network-fault resilience (9 workstreams) | All implemented; 2 real pre-existing proxy bugs found along the way |
| 2026-06-21 | Phase-43 S3 protocol completion, Phase-45 S3 data-plane perf, Phase-46 S3 write concurrency | All landed; found S3 async offload had never actually been engaging |
| 2026-06-22 | pgread zero-copy/CRC optimization; proxy upstream-bootstrap leak (>20GB) found+fixed | CPU/mem crisis-class proxy bug |
| 2026-06-23 | kXR_write pipelining (server-side write path) | Closed a real perf gap vs stock xrootd on concurrent writes |
| 2026-06-24 | kXR_pgwrite CSE retransmit machine; dashboard file viewer | Replaced a hard-fail with stock "accept-then-correct" semantics |
| 2026-06-25 | WebDAV locks → xattr-persisted (survives reload); Phase-57 W3 lock-expiry/lock-null | Superseded the old 1024-slot SHM lock table |
| 2026-06-26 | Phase-57 W2 ZIP member access (root://, WebDAV, S3); Phase-58 XRootD-parity batch | ZIP: stored+deflate, all 3 protocols; Phase-58: 9 features across auth/checksums/diagnostics |
| 2026-06-26 | Drop-in gap analysis (12-domain audit vs stock XRootD) | Identified 3 architectural blockers (never fixed by design) + prioritized feasible gaps |
| 2026-06-27 | CMS mesh fast-settle; lifecycle startup/shutdown speed | GSI keypool warm-up was 97% of worker boot time |
| 2026-06-2x | Phase-34 SciTags/pmark packet marking (`src/pmark/`) | 13 directives added to the shared `common` preamble, serving stream+WebDAV+S3 uniformly; firefly UDP reporting, flow-label encoding (see §10.1 for the later-found encoding bug), and metrics live-verified; WebDAV-TPC marking is build-verified only, not live-traffic-verified |
| 2026-06-27 | Proxy splice under-drain stall fix | The real cause of long-flaky `test_conformance_topologies` |
| 2026-06-28/29 | Fast teardown + mid-transfer resume (root:// + HTTP) | Sync cross-device commit by explicit design choice |
| 2026-06-29 | Remote root:// proxy full phase-space verification; S3 server user-metadata | Confirmed transparent proxy already forwards the *full* namespace phase-space |
| 2026-06-30 | AF-bridging + tap/relay/terminating-proxy monitoring stack (P1–P4b); full SSI framework (6 phases) + CTA tape service | GSI delegation-capture root cause found (non-obvious client-side flag gating) |
| 2026-07-02 | `kXR_writev` **and** chkpoint `kXR_ckpXeq` stock wire-framing fixes | Both closed same day — see §3 |
| 2026-07-04 | Unified kTLS (`brix_ktls`) across root:///WebDAV/S3 | Default ON; can't be demonstrated on this WSL2 kernel |

---

## 2. Native XRootD wire-protocol fidelity: the recurring bug class

Several of the most consequential bugs in this era share one shape: **our
client and our server agreed perfectly with each other, every in-tree test
was green, and both were wrong against the reference implementation.**
`lessons-migration-era-2026.md` §9 documents the canonical case
(`kXR_writev` framing) in full; the two points below extend that record.

### 2.1 `kXR_pgread` page alignment (file-offset framing)

`kXR_pgread` pages are aligned to the *absolute file offset*, not the start
of the read — an unaligned read's first page is short
(`kXR_pgPageSZ - (offset % kXR_pgPageSZ)`), so every later page lands on a
4096-byte boundary. This is required by XrdCl's `AsyncPageReader` and the
pgRetry-by-offset mechanism (each per-page CRC32c must cover an aligned
page). Empirically: `pgread(off=100, rlen=4096)` against stock XRootD emits
4104 page-stream bytes (3996+100, two CRCs); the old nginx encoder emitted
4100 (one full page, one CRC) — a real product bug, not a style nit. Fixed
in `xrootd_pgread_encode_pages()` (`src/read/pgread.c`), which now takes the
file offset and caps the first page. Buffer sizing must account for the one
extra page an unaligned read can span. Caught by
`test_pgread_wire_conformance.py::test_sub_page_unaligned_first_page_crc`
and `test_dropin_byte_for_byte.py`.

### 2.2 `kXR_writev` and chkpoint `kXR_ckpXeq` — both closed 2026-07-02

Stock XRootD frames `kXR_writev`'s header `dlen` as *only* the `N*16`-byte
descriptor block; the concatenated segment data streams after the frame,
recovered as `sum(wlen)`. Our stack counted the data inside `dlen` — self-
consistent between our client and server, but stock rejects it with
`kXR_ArgInvalid` and drops the link. The fix required a framing-layer
change (extend the read obligation after the descriptor block completes)
that touched client (`ops_file_rw.c`, `xrdc_send_ext`), server framing
(`recv.c`, `xrootd_writev_body_extra()`, `xrootd_grow_payload_buffer` which
*preserves already-received bytes*), the handler (`writev.c`), the proxy
(`forward_request.c`), and tap/observability (`tap_stream.c`, sums `wlen`
on the fly to stay frame-aligned). Design constraint: **the framing layer
never rejects** — a malformed vector still dispatches so login/auth/write
gates run first; only the *handler* produces the parity error, then the
link is dropped (once the descriptor block is in doubt, the trailing byte
count is unknowable and there is no resync).

The embedded-checkpoint variant, `kXR_ckpXeq`, was flagged as the next
instance of the *same bug class* when the writev fix landed (documented as
an open item in `lessons-migration-era-2026.md` §9.4) — **and was fixed the
same day**, closing that open item. Stock requires the outer chkpoint frame
`dlen == 24` (the embedded sub-request header only, carrying the *outer*
streamid) and streams the sub-request payload after the frame
(`XrdXrootdXeqChkPnt.cc`); our `chkpoint_xeq.c` previously expected the
whole sub-request inline. Fix: a two-stage `cur_body_extended` extension
(`xrootd_ckpxeq_body_extra()` delegates stage 2 to the writev extension for
embedded writev), stock error ordering (streamid mismatch → dlen!=24
"Request length invalid" → embedded-chkpoint/truncate-with-data invalid,
byte-count cross-check *before* the ckp-active check so violations always
drop the link), and `kXR_Unsupported` for multi-file chkpoint writev (like
stock). 15 new tests in `tests/test_chkpoint_stock_framing.py`, including 5
"source-contract pin" tests that assert the writev.c↔chkpoint_xeq.c cross-
references stay in sync — a mechanical guard against the two paths drifting
apart again.

**Rule extracted (applies beyond this codebase):** any wire opcode this
stack speaks needs at least one test where the *other end is stock*. Green
client↔server proves internal consistency, not wire correctness. "Recover
the layout by size heuristics" (the old writev server derived N from
`n*16 + sum(wlen) == dlen`) is itself a red flag — ambiguity in a decode
heuristic usually means the layout itself was invented, not observed.
Another instance of the same discipline, found while chasing an earlier
proxy `kXR_mv` bug (§5): the real wire payload is `old_path + " " +
new_path` with `arg1len = len(old_path)`, confirmed against actual `xrdfs`
traffic rather than assumed from the header struct.

### 2.3 `kXR_pgwrite` CSE (checksum-error) retransmit machine (2026-06-24)

Replaced a prior hard-fail with stock's real "accept-then-correct" model:
verify every page, write *all* pages (good and bad) to disk, reply success
with a `pgWrCSE` trailer listing bad-page offsets; the client resends each
bad page with `kXR_pgRetry` set; a per-handle "Fob" (fault-observation
buffer?) tracks uncorrected pages; `kXR_close` returns `kXR_ChkSumErr`
while the Fob is non-empty, keeping the handle open so the client can
correct and re-close. `chkpoint_xeq`'s embedded pgwrite still hard-fails via
its unchanged decode path — a deliberate scope exception carried into §15,
not a gap in this fix. ASAN was never run on the CSE state machine; treat
that as an open verification item.

A bonus bug found later while extending chkpoint support (Phase-58):
`kXR_chkpoint` on a path-less/SSI handle called `strlen(NULL)` and crashed
the worker — now guarded.

Two wire subtleties worth remembering: (1) for a CSE frame, `hdr.dlen`
covers only the fixed 20-byte body (24 total with the header) — the
`pgWrCSE` trailer follows as separate `data`, exactly like pgread page-data;
the body CRC32c covers only the fixed head, `cseCRC` covers `dlFirst..bof[]`
— getting `dlen` wrong (`=24+cse_len`) causes a client/test timeout, not a
clean error. (2) A `kXR_pgRetry` resend has the *same* `(offset, len)` as
the original write, so the existing `kXR_recoverWrts` replay-detection
logic short-circuited retries before `fob_del` ran, permanently wedging
`kXR_close`. Fixed with an explicit `!is_retry &&` guard on the replay
check. Caps: `kXR_pgMaxEpr=128`/request, `kXR_pgMaxEos=256`/file →
`kXR_TooManyErrs`. `tests/test_pgwrite_cse.py` (20 raw-wire tests) plus 5
new differential-vs-stock cases in `test_conf_pgio.py`.

---

## 3. Read/write data-plane performance: the long optimization arc

Phases 29 → 30 → 31 → 32 → 33 (plus S3's 45/46) form one continuous
throughput-and-latency effort. The headline lesson, stated once and true
throughout: **this WSL2 dev host has no trustworthy throughput signal.**
Every phase that tried to draw a Gbps conclusion here either got it wrong
(kTLS "should help" → measured 2.4–5.5x *slower*) or had to fall back to
deterministic proxies (syscall counts, byte-identical output, strace).
Phase-33 explicitly named this "P0: a real perf host is a hard prerequisite"
and deferred the highest-leverage remaining work (`PIPELINE_MAX` raise +
concurrent-AIO recv flip) until one is available. A later correction
(2026-07-15) additionally discredited *any* "it's just host load" verdict
recorded before that date — see `host_load_excuse_debunked` in memory; if
citing an old "flaky under load" conclusion from this era, re-verify it.

### 3.1 What actually shipped and its measured effect

| Phase | Change | Result |
|---|---|---|
| 29 P1/P2 | `out_ring` FIFO response queue; cleartext sendfile pipelining | Landed; the multi-response-in-flight foundation everything else builds on |
| 29 P4 | kTLS (`SSL_OP_ENABLE_KTLS`) | **Regression** on this hardware: software kTLS ON = 128–175 MB/s vs OFF (userspace OpenSSL/AES-NI) = 309–970 MB/s, 2.4–5.5x slower. Kept opt-in (`xrootd_ktls`, default off then; unified `brix_ktls` later defaulted ON as a transparent no-op — see §9) |
| 29 P3 | AIO read pipelining (decouple reads from `XRD_ST_AIO`) | Spec'd, explicitly deferred — disconnect-mid-AIO UAF guard unexercisable in this env |
| 30 M0/M1 | P0 bugfixes (dup rate-limit charge, 3-way parallel HW CRC32c, `XROOTD_OPTIMIZE=v2/v3/native` build profile, single-bucket latency histogram, `F_SETPIPE_SZ` 1MiB, reused AIO tasks); redir_cache O(n)→hash, cache-line-aligned metrics, length-aware path-prefix match | Complete, zero regressions. M1.4 (an invasive resolve-once refactor across ~30 security-critical sites) was deliberately deferred out of this phase and folded into the then-concurrent Phase-8 namespace refactor instead of being run standalone. This phase also corrected a false assumption relevant to CLAUDE.md invariant #2: HTTP GET over TLS does *not* buffer whole files (it uses `in_file=1` + `ngx_http_output_filter`), so the `b->memory=1` vs. cleartext-sendfile distinction is stream-plane only — the HTTP path must never be switched to `b->memory=1` |
| 31 | Memory-budget streaming: SHM handle-table shrink, PUT body streaming, SHM-global budget + backpressure, windowed memory reads | Complete; **found and fixed a real corruption bug** — see §3.2 |
| 32 | WS1 kTLS (config-only), WS2 multi-chunk sendfile builder, WS4 `preadv2(RWF_NOWAIT)` page-cache fast path, WS5 config bundle | Done; WS3 (concurrent-AIO front-end) foundation only, the recv-state-machine flip deferred |
| 33 | P2 fixed-cost cuts: rate-limit key memoization, O(1) bound-handle-slot cache, batched access-log writes; build default flipped to `-O3 -march=x86-64-v2 -fno-plt` | Done; P1 (the big one) deferred to a real perf host |
| 45 (S3) | ListObjects O(page) not O(bucket); kill redundant GET fstat; zero-copy multipart via `copy_file_range` | Done, strace-proven (5-object page → exactly 5 lstats, was bucket-wide) |
| 46 (S3) | Offload spooled PUT / aws-chunked decode / multipart Complete onto the thread pool; PUT parent-dir fast-path; skip FRM residency probe when FRM is off | Done; **found S3 async offload had never actually been engaging** — see §7.3 |
| pgread (2026-06-22) | Zero-copy `preadv`-direct-into-wire-buffer + in-place CRC; a 3-way parallel copy+CRC variant (`xrootd_crc32c_copy_hw3`) was also kept despite only a ~4% marginal gain, because the path is memory-bandwidth-bound and the same code helps `kXR_pgwrite`'s unavoidable copy | **The real win**: read-path CRC+copy dropped from ~27.6% to ~10% of CPU; a 14.8% memcpy band and a 12.8% serial-copy band both went to zero |
| write (2026-06-23) | `kXR_write` pipelining (recv/pwrite overlap) | n=8 concurrent writes: ~1550–1650 → ~1900–2300 MiB/s, moved from behind stock xrootd to ahead/even |

### 3.2 The pool-churn UAF that masqueraded as two different bugs

Phase-31's read-buffer trim (free+realloc scratch buffers to shrink memory
under budget pressure) caused SIGSEGVs on large `kXR_read`→`kXR_readv`
sequences. Root cause: `read_scratch`/`write_scratch`/`read_hdr_scratch`
were **nginx-pool-backed** (`ngx_palloc`/`ngx_pfree`); the trim's
free+realloc churned the pool's large-allocation list under stale pointers
— a use-after-free. The fix (switch these three scratch buffers to raw
`ngx_alloc`/`ngx_free`, freed explicitly on disconnect) turned out to *also*
fix a separate, pre-existing, unrelated-looking bug: a TLS large-multi-read
`EFAULT` ("Bad address") that had been attributed to something else
entirely. Both bugs were the same pool-churn cause wearing different
costumes. Lesson: when two "unrelated" crashes share a code path that does
manual pool free/realloc, suspect one root cause before debugging them
separately.

### 3.3 Attribute the flame-graph leaf to its *caller* before optimizing it

The pgread optimization session (2026-06-22) profiled a `clear_page_erms`
hotspot (~12% CPU) that looked like it justified a per-worker read-buffer
pool. Careful attribution after landing the real fix showed 98% of that
symbol was kernel socket/skb page allocation on the loopback TCP *send*
path (69.8% under `queue_response_chain`, 28.6% under `flush_pending`) —
only 1.6% was the module's own read buffer, which was already reused
per-connection. Building the pool would have added thread-pool-lifetime
risk for a 1.6% win that was also a loopback-bench artifact (a real NIC
wouldn't show the double-copy). The zero-copy `preadv`-into-wire-buffer
change (§3.1) was the one code change that actually mattered; the send
path itself is kernel-bound and not module-controllable beyond what was
already correct (`tcp_nodelay`, single coalesced writev, sendfile for
plain reads). `pgread`'s `[CRC(4)][data]` interleaving is fundamentally
incompatible with sendfile — that copy is structural, not a bug.

### 3.4a Write pipelining required a new teardown-safety invariant

Landing `kXR_write` pipelining (recv/pwrite overlap, §3.1) broke an implicit
old invariant that connection teardown relied on: exactly one AIO write in
flight per connection at a time. With multiple writes overlapping, teardown
could race a still-in-flight `pwrite`. Fixed with an explicit deferred-
teardown mechanism (`xrootd_defer_teardown_if_writing()` /
`xrootd_run_deferred_teardown()`, gated on a `wr_inflight` counter) —
validated via disconnect-mid-write stress testing. The full pytest suite and
an ASAN pass on this change were not completed in the session that landed
it, so treat the pipelined write path as needing that verification before
leaning on it further.

### 3.4b A GSI test flake wrongly blamed on WSL2 host load

During Phase-33 perf work, a GSI-related test flake was initially attributed
to "WSL2 resource contention" — the kind of verdict §3's intro already
warns to re-verify. The actual root cause was a harness bug: a PKI-
regeneration race in the test fixtures, not host load at all. Consistent
with the standing rule (`host_load_excuse_debunked`): before accepting "host
overloaded" as a diagnosis, get a concrete mechanism.

### 3.4 The proxy splice under-drain stall — the real cause of long-standing flakiness

`test_conformance_topologies` had been intermittently failing on `mesh`/
`proxy` topologies (never `cluster`/`mirror`) for a long time, previously
blamed on CMS mesh timing or general "load." The actual cause (found
2026-06-27): stock XrdCl issues one 5MB `kXR_read`, which the transparent
`xrootd_proxy` forwards via a zero-copy `splice(socket→pipe)` fast path
(`src/proxy/events_splice.c`). **On WSL2, that splice systematically
under-drains** — it returns ~64–128KB then `EAGAIN` with data still queued
in the kernel (even with `F_SETPIPE_SZ` set to 1MB), so the read crawls at
~75KB/s past the 60s client timeout. `xrdcp` never reproduces this because
it chunks reads (never triggers the splice fast path); only a single large
`kXR_read` does — which is exactly what real `XrdCl` does and the test
harness's chunked client didn't.

Fix (self-healing fallback): when `splice(upstream→pipe)` returns `EAGAIN`
with `splice_downstream < splice_total` (body remains queued), switch the
*remainder* of that transfer to the buffered-recv relay path instead of
retrying splice. Zero-copy is preserved for the common case (whole body
already buffered completes via the normal splice-done path and never hits
the `EAGAIN` branch). A first attempt using `MSG_PEEK` at the `EAGAIN`
point to decide whether to fall back was a dead end — the crawl's `EAGAIN`s
hit a momentarily-empty, TCP-paced socket, so peek saw nothing and the
fallback only ever triggered after the full 60s timeout anyway. Result:
20/20 and 15/15×2 reads at 0.04–0.06s, 0 stalls (was 60s intermittent).

---

## 4. CMS clustering / manager-server protocol

### 4.1 Real wire-format interop (`XrdCms`/`YProtocol`)

Getting nginx-xrootd to interoperate with a real `cmsd` required extracting
the exact wire format from XRootD 5.9.2 source (`YProtocol.hh`,
`XrdCmsLogin.cc`, `XrdCmsParser.cc`, `XrdOucPup.cc`). The header is 8 bytes:
`streamid(u32) rrCode(u8) modifier(u8) datalen(u16)`. The concrete bug this
found: `XrdOucPup` encodes strings as `[2B BE len][data]` with **no tag
byte** (length includes the NUL) — nginx was originally sending a
tagged-short instead, breaking SID/Paths/ifList/envCGI fields. All 4 interop
directions (nginx-data↔real-mgr, real-cmsd↔nginx-mgr, mixed pool,
multi-tier) are validated in `tests/test_cms_mesh_interop.py` (21+ tests,
including tri-protocol cms://+root://+https:// meshes). Test-harness
gotchas: launch with `start_new_session=True`; a real manager defaults to a
~90s `cms.delay startup` before redirecting (add
`cms.delay startup 5 servers 1 lookup 2` to test manager configs); `xrdcp`
needs a *double* slash (`root://h:p//abs/path`).

### 4.2 CMS mesh fast-settle (2026-06-27)

Same-host CMS meshes (all nodes booting together) took **1–8 seconds** to
register with their manager. Root cause was two compounding defects in
`src/cms/connect.c`: a fixed 1-second `NGX_XROOTD_CMS_INITIAL_DELAY` before
the first connect attempt, and a *refused* connect (manager's listen socket
not yet up when the whole mesh boots simultaneously) jumping straight to
exponential backoff seeded at up to 6 seconds. Multi-tier meshes compound
this per tier.

The debugging subtlety: on loopback, `connect()` to a not-yet-listening
port returns `EINPROGRESS`, so the refusal never surfaces in the
`connect()` failure branch at all — it surfaces later as `recv() failed
(111 Connection refused)` in the *read* handler, which calls the retry
scheduler directly. Routing a fast-retry fix only through the `connect()`
failure path (the first attempt) would have been silently ineffective; the
fix had to be folded into `ngx_xrootd_cms_schedule_retry()` itself so every
caller gets it.

Design: gated on `!ever_logged_in` (a fast-retry mode can't run forever —
it only exists before first successful login) plus a bounded window;
loopback vs remote get different tuned profiles (loopback: 0ms initial
delay / 10ms retry / 2s window; remote: 10ms / 75ms / 3s), with retry
floored at 10ms (`FASTRETRY_FLOOR`) so a misconfigured 0 can't busy-spin.
On window expiry, one actionable WARN fires, then the existing
doubling+jitter backoff takes over. This is documented in memory as an
explicit `idle_cpu_timer_family` safety check — the standing rule against
0ms self-rearming timers.

Test gotcha: `ngx_log_debug*` calls are compiled out without
`--with-debug`, so the fast-retry test can't count debug lines; it instead
asserts the eventual backoff WARN appears at ~2s (proving the window held
off the slow-backoff path) and stays sparse (proving no spin).

### 4.3 IPv6 completion (Phase-36)

One recurring root-cause defect explained a long tail of IPv6 gaps: IPv6
literals were re-emitted into `host:port` wire strings and HTTP headers
*without brackets*, so `2001:db8::1:1094` was unparseable downstream. The
decisive asymmetry that proved it: `read/locate.c` bracketed correctly
(`S%c[%s]:%d`) but `manager/registry.c`'s `xrootd_srv_locate_all` did not
(`%sS%c%s:%u`, bare host) — so IPv6 worked for a *standalone* node but broke
across clustering, redirect, and proxy. The fix was one shared helper,
`xrootd_format_host_port()` (`src/compat/host_format.c`), applied
bracket-on-emit at every site (registry, control/redirect, both webdav
proxy Host paths, native-TPC URL rebuild, dashboard admin API, TPC curl
`CURLOPT_RESOLVE`). Socket/config-parse layers were already IPv6-clean —
the audit deliberately did *not* invent dual-stack listen work that wasn't
needed. Verified complete with 92 passed / 2 intentionally-xfailed
(same-host IPv6 native-TPC loopback pull correctly SSRF-denied; WebDAV
plaintext-egress correctly refused) across 7 dedicated `[::1]` test files.
One test-only fix along the way: a metrics label-cardinality test had a
stale magic-number cap (`<=16`) that a legitimate new `depth` label
(from the pipelining work) pushed to 17 — replaced with an explicit
allow-list-subset check, which is a stronger guard than a raw count cap.

PyXRootD's client cannot parse `root://[::1]` literals, so root:///CMS/TPC
IPv6 tests had to be written as raw-wire socket tests, not through pyxrootd.

---

## 5. Proxy mode: an incident-driven history

The transparent `xrootd_proxy` (native XRootD-to-XRootD proxy) accumulated
features across several phases, but its most important history is a series
of concrete production-shaped bugs, each with a distinct root-cause class.

| Bug | Root cause | Fix |
|---|---|---|
| Bootstrap reader stall (edge-triggered epoll) | `xrootd_proxy_read_handler` `return`ed after each bootstrap message; when handshake+protocol+login all arrived in one TCP segment (warm connection), no new epoll edge fired | Loop `continue`s until `recv()` returns `NGX_AGAIN`, draining all buffered messages per event — the classic edge-triggered rule |
| FH exhaustion after 16 open/close cycles | `kXR_close` relay handler never freed the local file-handle slot | Capture `local_fh` before FH translation; free the slot on `kXR_close`+`kXR_ok` in the relay |
| Upstream-bootstrap memory leak, >20GB, 95.7% CPU | `xrootd_proxy_abort` signals teardown via `ctx->proxy = NULL` but never touches `proxy->state`; the read loop's exit guard keyed off `proxy->state` — two liveness signals drifted apart on the error path, so an aborted-but-not-freed proxy re-processed the same buffered rejection frame forever (UAF busy-loop) | One guard at the top of the read loop: `if (ctx->proxy != proxy) return;` — keys off the *same* signal the abort path sets, catching abort from any branch |
| `xrootd_proxy_pool_shutdown()` SIGSEGV on HTTP-only workers | `proxy_pool` is a zero-init BSS `ngx_queue_t`; on a worker with no stream main-conf, `init_process` returns before `xrootd_proxy_pool_init()` runs, but `exit_process` calls `pool_shutdown()` unconditionally — the NULL sentinel makes `ngx_queue_empty()` misread as "non-empty," and the dequeue derefs NULL | Guard `if (proxy_pool.next == NULL) return;` at the top of shutdown. A stale code comment had falsely claimed this path was already safe |
| `xrdcp --no-retry`/`--retry 0`/`--max-stall 0` didn't actually fail fast | The client's stall-window computation ignored the `no_retry` flag entirely | Honor `no_retry` in the stall-window computation |
| Splice under-drain 60s stall | See §3.4 | Self-healing fallback to buffered recv |
| Stream `wbuf` leak under a slow consumer | Never freed after a deferred flush (~128KB/request) | `src/proxy/events_write.c` fix, found incidentally during Phase-39 |
| Splice wire corruption on resume | Partial 8-byte header re-sent from the start instead of resuming mid-header | `src/proxy/events_splice.c` fix, found incidentally during Phase-39 |

### 5.0 Proxy feature buildout (phases 2/3 and later)

Beyond the incident list above, the transparent proxy accumulated a real
feature set across two buildout passes: upstream TLS (certificate
verification + SNI), lazy-open `kXR_bind` secondary-connection handling,
upstream reconnect and multi-upstream round-robin, connect/read timeouts,
path rewriting, SSS credential delegation
(`xrootd_sss_build_proxy_credential`), `kXR_endsess` forwarding, and
`kXR_readv` multi-handle lazy-open queuing; then, in a later pass,
Prometheus metrics, a per-handle audit log, bearer-token auth bridging
(`xrootd_proxy_auth anonymous|forward`), per-upstream credential isolation,
a path-operation audit log, transparent `kXR_wait` retry on open, and
additional counters. The admin REST API that manages the SHM-backed proxy
pool (Phase-23, §1) is disabled by default (403) unless configured with
either a CIDR allow-list or a file-based bearer secret (compared with
`CRYPTO_memcmp`), supports a `require_both` AND-mode, rejects (rather than
sanitizes) invalid input against a whitelist, mandatorily audit-logs every
write, and deliberately does *not* expose an unauthenticated backend-list
GET endpoint, to avoid leaking topology to an unauthenticated caller.

### 5.1 The leak-hunt method (worth keeping as a reusable playbook)

The >20GB leak postmortem (`docs/09-developer-guide/postmortem-proxy-retry-leak.md`)
distilled a reusable method: for a 100%-CPU spin, get a `gdb -p PID -batch
-ex 'bt 25'` backtrace **first** — it named the actual loop in seconds,
after RSS-attribution heuristics had wasted hours mis-blaming CMS mesh
timing, compression, and partial handshakes (all of which turned out to be
bounded in isolation). Repro safely inside
`systemd-run --user --scope -p MemoryMax=20G -p MemorySwapMax=0` (noting the
scope-as-background-task pattern is itself flaky — a child can reparent
uncapped). Track *trailing-minimum* RSS, not instantaneous RSS — fixtures
spike and return, but a real leak ratchets the floor upward across runs.
Crucially: **a leak fix is not verified by "5/5 tests pass."** The first
attempted fix (a per-connection failure-count cap) did not actually work —
the same test suite passed both before and after while the leak kept
spinning, because the cap's code path was never reached (the same proxy
object survived across the whole run, never re-allocated, so a
re-dispatch-count cap was irrelevant). It was only proven wrong by
re-running under the full suite and catching the spinner with gdb a second
time. The house rule that came out of this: chaos/negative tests must
assert resource bounds (CPU/RSS/worker-survival), not just error return
codes.

A related build/ABI incident from the same fail-fast investigation: phase-55
(storage-driver abstraction, see `lessons-migration-era-2026.md` §0/§2) had
broken the standalone client build because `checksum_core.c` pulled in
`ngx_config.h` transitively via `sd.h`. Rob's explicit call was to keep the
SD-driver seam as-is and instead make the SD POSIX raw surface
(`sd.h`/`sd_posix.c`) itself ngx-free via `XRDPROTO_NO_NGX` shims, rather
than decoupling `checksum_core` from the seam — i.e. the client-build
constraint was pushed down into the driver layer, not worked around at the
checksum layer.

### 5.2 Design confirmations from later verification work

`remote_root_proxy_full_phasespace` (2026-06-29) empirically confirmed
that the transparent proxy already forwards the *entire* metadata/namespace
phase-space to a root:// origin (mkdir, put, ls, stat, chmod, mv, rm,
xattr set/get/ls all round-trip) — because `xrootd_proxy_dispatch` relays
by raw `requestid` with no opcode whitelist, every opcode reaches the
origin's full POSIX VFS. This is distinct from (and ahead of) the read-only
`sd_xroot` cache-fill backend, which deliberately only speaks a read-side
subset (login/open/read/write/trunc/sync/close/query/mkpath/delete) — the
two "remote root://" code paths serve different purposes and neither is a
gap in the other.

---

## 6. Network resilience (Phase-39)

Nine workstreams (read/handshake/send-drain deadlines, `TCP_USER_TIMEOUT`+
keepalive, TPC stall bounding + registry reaper + curl-cancel-on-disconnect,
proxy bugfixes, cluster/CMS dead-peer staleness+jitter, WebDAV staged-commit
PUT durability, S3 multipart-upload reaper, and connection-cap overload
shedding) were all implemented and built in one sustained session
(2026-06-15), deliberately going further than stock XRootD's fault
tolerance while keeping every new behavior opt-in (default off). Beyond the
two proxy bugs already listed in §5, this phase left several mandatory
correctness rules worth keeping in mind for any future timer/AIO work in
this codebase:

- A read timer is a **UAF risk unless disarmed before AIO/SENDING
  handoff** — timers must be armed on genuine incompletion and disarmed on
  quiescence via an idempotent flag, never touched mid-pipelining.
- The TPC reaper must mark-then-reclaim using the registry's own unique
  64-bit id as the generation counter — no separate generation counter
  needed.
- A pre-identity connection cap (before login, no streamid exists yet) must
  be a plain TCP close; `kXR_wait` isn't available pre-login.
- `NGX_CONF_NO_TIMER` doesn't exist in nginx; the pattern used throughout
  is "default 0 = disabled, `>0` guards the unsigned `ngx_msec_t`."

Test-environment note: self-launched servers via bash `&` (especially with
`master_process off`) spuriously report shell exit code 144 on this WSL2-RT
host — drive nginx via Python `subprocess.Popen` instead, as
`test_netfault_stream.py` does. Genuine packet-loss testing via
`tc qdisc ... netem loss 20%` inside an unprivileged
`unshare --net --user --map-root-user` namespace was verified to work on
this host with no sudo required, and exists as an optional second test tier
alongside the primary root-free stall/partial/disconnect fault-injection
proxy.

---

## 7. S3 protocol: from SigV4 cleanup to full completion

### 7.1 Phase-9 — SigV4 crypto efficiency (2026-06-12)

A cleanup phase, notable mainly because — unlike several others in this
era — it left **zero** dead code behind on its own: crypto singletons
(`xrootd_crypto_init`/`_cleanup`, called once per worker in
`init_process`/`exit_process`), a cached signing-key derivation, `timegm(3)`
replacing a hand-rolled civil-date function, and removal of a whole
now-redundant header extraction file. `CRYPTO_memcmp` was preserved at
both verify sites.

### 7.2 Phase-43 — full S3 protocol completion (2026-06-21)

Six workstreams, the most consequential being **W0: AWS chunked-transfer
decoding**. Modern `aws-cli`/`boto3` send
`x-amz-content-sha256: STREAMING-*` with chunk-signature framing embedded
*inside* the HTTP body (distinct from HTTP chunked transfer encoding).
Before this fix, that framing was stored verbatim into the object — silent
data corruption, or a 400 if it happened to trip the codec-reject path.
Fixed with a dedicated streaming state machine
(`src/s3/aws_chunked.{c,h}`) wired into `s3_put_streaming` *before* the
compression-codec block. Chunk-signature cryptographic verification was
deliberately not added — header SigV4 plus TLS already cover integrity,
so an inert extra check wasn't worth the complexity.

Other W-items: a generalized checksum table (crc32/crc32c/sha1/sha256/
crc64nvme, one descriptor table, edge-encoded per protocol — see §8); List
Objects V1 (marker pagination, no `KeyCount`, alongside the existing V2);
S3-specific conditional GET semantics (the one real gap found was
`If-Modified-Since` needing S3's "before" comparison rather than exact
match — a future date must return 200, not 304); conditional PUT via a
pre-commit confined-stat check (explicitly *not* `renameat2`, to avoid
cascading into the beneath/impersonation seam — documented as an accepted
micro-TOCTOU rather than a silent gap); and tag/canned-subresource support
(`user.s3.tagging` xattr, `?tagging`, canned `GetBucketAcl`/`Versioning`
responses).

### 7.3 Phase-45/46 — S3 data-plane performance, and a real "never engaged" bug

Phase-45 fixed a genuine O(bucket) memory/syscall blowup: the old
`ListObjects` walker allocated a **fixed 65536-entry, ~273MB array** per
list request and `lstat`'d every object in the whole subtree on every page.
Fixed to a growable pooled array plus `readdir` `d_type` classification
(falling back to `lstat` only on `DT_UNKNOWN`), with per-object stat done
only for the emitted page slice — strace-proven (a 20-object bucket with
`max-keys=5` now does exactly 5 `lstat`s, not 20). The same phase also
killed a redundant per-GET `fstat`: a `stat_current:1` bit was added to
`xrootd_vfs_file_s`, set in `adopt_fd` and cleared in `xrootd_vfs_write` to
preserve the existing "live fstat after write" contract — shared with the
WebDAV GET path.

Phase-46's most important finding was not a new feature but a **latent bug
discovered by turning on the offload it was building**: S3's async
thread-pool offload for PUT bodies had *never actually been engaging* for
the standard configuration. `xrootd_s3 on` lives in an nginx `location{}`
block, but S3's postconfiguration only resolved `common.thread_pool` from
the *server*-level loc-conf — so every PUT, even in-memory ones, had been
running synchronously on the event loop the whole time. (WebDAV already
had the correct lazy per-request pool resolver; S3 simply never got it.)
Fixed with a lazy resolver `s3_thread_pool(cf)` mirroring the WebDAV
pattern. Turning the offload on then exposed a second, previously-latent
bug: the async PUT completion path had never set the ETag response header
(the synchronous path did) — invisible until async code actually ran a
test that checked for it. Lesson generalized: **a "done but never
exercised" code path can hide bugs indefinitely; the safest way to find
them is to make the path actually run**, ideally under strace/instrumented
proof rather than trusting that a green test suite means the intended
code path executed.

---

### 7.4 S3 user metadata + `sd_s3` driver parity

`x-amz-meta-*` user metadata is supported on PUT/GET/HEAD and through
`CopyObject`'s COPY/REPLACE semantics, stored as a `user.s3.usermeta` xattr
blob, with a copy-self+REPLACE fast path that skips the byte copy entirely
when only metadata changes. The `sd_s3` storage-driver got matching parity
(`sd_s3_get_meta`/`sd_s3_set_meta`), which required adding
`sd_s3_sign_ext` — SigV4 signing over arbitrary extra `x-amz-*` headers —
so metadata set/get works against real AWS, not just the module's own
anonymous test server.

## 8. Checksums, compression, and other cross-protocol edge encoding

### 8.1 CRC64 (2026-06-14)

Added across root://, WebDAV, S3, and the native client as `crc64`
(CRC-64/XZ) and `crc64nvme` (CRC-64/NVME, AWS S3's convention) — **two
genuinely different polynomials**, not interchangeable, and stock XRootD
ships no CRC64 calculator at all, so these names are this gateway's
de-facto convention (recorded as CLAUDE.md invariant #9). The design rule
that generalizes: **per-protocol encoding lives at the edge, never in the
checksum kernel** — root:// and legacy WebDAV emit 16 lowercase hex; S3 and
RFC 9530 emit base64 of the 8 big-endian bytes. Gotchas: reflected
polynomials are not the same as their "normal" form (the lookup table must
be built from the bit-reversed constant); an S3 PUT checksum mismatch must
`unlink` the object *before* replying 400 so a bad object never survives
(done for both sync and async paths; the streaming `x-amz-trailer` variant
was explicitly left unparsed as a known follow-up, not silently dropped).

### 8.2 Compression (Phase-42, completed prior to this era but referenced throughout)

Stock XRootD only ever speaks DEFLATE/zlib (client-side ZIP reads, a
vestigial `kXR_compress`); everything past gzip/deflate — lzma, zstd,
brotli, bzip2, lz4, outbound compression, and inline root:// read/write
compression — is a deliberate off-by-default swiss-army extension,
invisible to stock peers unless explicitly negotiated. root:// inline
compression frames whole-request ranges, not block descriptors, and
deliberately excludes `kXR_pgread`/`readv`/`kXR_pgwrite` to preserve the
per-page CRC32c invariant. One build-governance finding from this phase
still matters: a full `nginx -t` dlopen of the *per-module* dynamic `.so`
set fails on circular cross-module symbol dependencies under `RTLD_NOW` —
no load order can satisfy a cycle — which is why non-filter modules were
later bundled into one combined `.so` (Phase-47).

### 8.3 kTLS unification (2026-07-04)

`brix_ktls` unifies kernel-TLS enablement across root://, WebDAV, and S3
behind one directive, default **ON** (a transparent no-op when the
cipher/kernel can't offload — this differs from Phase-29's earlier
opt-in-only `xrootd_ktls`, whose 2026-06-13 measurement showed a
*regression* on software-only kTLS; that measurement is still true on this
hardware and is exactly why the directive stays a safe no-op rather than
forcing behavior). Two config-wiring gotchas worth remembering for any
future shared-`common`-conf field: (1) WebDAV and S3 init/merge their
shared `common.*` fields *manually* (not via the generic shared
init/merge helper) — a new common field needs the explicit
`NGX_CONF_UNSET` + merge call added in *both* places or it silently stays
zero from `pcalloc`, with no warning. (2) `brix_webdav` is set at
*location* level but TLS/proxy-certs/`brix_ktls` are *server* level —
code that reads the server-level conf must not gate on the location-level
`common.enable` flag, which is unset at server scope. On this specific WSL2
6.18.6 kernel, kTLS TX is documented as outright broken (aborts encrypted
GETs), and this nginx build lacks `NGX_HAVE_OPENSSL_SSL_SENDFILE`, so
engagement can't be demonstrated here — needs verification on a mainline
kernel before relying on the "default ON" claim in production.

---

## 9. Lifecycle, mirroring, resume, rate limiting, and the dashboard

### 9.1 Lifecycle startup/shutdown speed (2026-06-27)

Baseline measurement (2 workers, WSL2): cold start ≈19–25ms, reload
≈13–41ms, respawn ≈31ms, shutdown ≈22ms. The dominant cost — **~97% of
per-worker init** — was `xrootd_gsi_keypool_init` synchronously generating
all 64 `ffdhe2048` DH keys on the event thread at boot, even though the
async off-thread refill machinery for steady-state operation already
existed and simply wasn't being used at warm-up. Fix: seed only 4 keys
synchronously, fill to 64 off-thread via the GSI server's thread pool.
Result: keypool cost 16ms→1.2ms/worker, `init_process` 16-18ms→1.4ms,
respawn 28ms→16ms. The fallback (a server with no thread pool configured
falls back to the old full synchronous warm-up) means this optimization is
silently inert unless `thread_pool`/`aio threads` is configured — the test
harness itself needed a `thread_pool default threads=4` directive added to
its generated config before it could observe any speedup at all, which
initially looked like "no change" and cost debugging time before the
missing directive was spotted.

Rob also asked whether master-`prepare` (pre-fork) could be sped up the
same way ("Stage 2b"); this was investigated and explicitly rejected — the
remaining ~2-3ms cost is the GSI `X509_STORE` build (CA+CRL PEM parse),
which cannot be deferred because it's needed before the first TLS
handshake, and its cost scales with CA-bundle size, not with anything this
codebase controls. A noted future idea, not implemented: dedup the store
build across server blocks that share the same CA path.

WebDAV's shutdown drain has its own behavioral rule, distinct from root://'s
clean-FIN choice: new requests arriving during drain get `503` with
`Retry-After` and `keepalive=0`, rather than being accepted onto a
connection that's about to close.

Fast teardown/resume (root:// and HTTP, 2026-06-28/29) discovered that
*client-side* download/read resume already worked — the actual gap was the
server serving shutdown too slowly. The dominant teardown lever turned out
to be **stopping background timers** (guarding self-rearming timers with
`!ngx_exiting`), not sweeping the connection array — idle connections have
no timer and never pinned worker exit. Design decisions worth remembering:
root://'s retry signal on drain is a clean FIN, not `kXR_wait`/redirect
(`kXR_wait` stalls the client ≥1s on a dying host; self-redirect trips its
own loop guard); upload-resume partial-file identity is deterministic and
keyed off the *authenticated* principal
(`<final>.xrdresume.<hex16(SHA-256(principal\0final))>.part`) so another
identity can't name or reclaim someone else's partial; and Rob explicitly
chose **synchronous** cross-device commit (the close/final-chunk reply
blocks until data reaches final storage) over an async model, even though
it means a large cross-device copy can happen inline in the event loop /
PUT handler — durability tracked via a `.commit` marker plus a worker-0
startup reaper for stranded moves.

### 9.2 Traffic mirroring, including write mirroring (Phase-24, W1–W3)

Read-only HTTP/WebDAV and XRootD-stream shadow replay landed as Phase-24
(2026-06-12); write mirroring (mkdir/rm/rmdir/mv/truncate/chmod plus
WebDAV PUT/DELETE/MKCOL/MOVE/COPY plus stream data writes) followed as a
separate effort. The load-bearing safety rule: mirroring writes is off by
default, and **the shadow must be an isolated namespace** — replaying
writes into a shadow sharing the primary's filesystem corrupts data, so
the pre-existing read-only mirror test topology (which deliberately shares
a filesystem) must never be repurposed for write-mirror testing. A
two-guard gate enforces this in code too: write opcodes/methods are
excluded from the default opcode/method masks, so a write mirror needs
*both* an explicit opcode/method-list entry *and* `xrootd_mirror_writes
on`. One implementation subtlety for HTTP PUT mirroring: the mirrored
request body must be an *independent* clone of the buffers (not shared
`pos`/`file_pos` with the primary handler reading the same body), with a
cloned Content-Length computed from the sum of the cloned buffer sizes so
it can never desync from what's actually sent. Stream-plane data-write
mirroring (W3) was implemented and build-clean but its end-to-end runtime
validation and ASAN pass were never completed in the session that wrote
it — flagged as a hard prerequisite before enabling it in production.

A separate implementation subtlety that cost a debugging cycle on the
HTTP mirror surface: doing the subrequest-takeover logic in nginx's
CONTENT phase simply never fired for the mirror subrequest; moving it to
PRECONTENT worked. Self-mirror loop prevention uses an `X-Xrootd-Mirror: 1`
header that a PRECONTENT handler checks and declines on if already present.
The HTTP mirror also defers only the client connection's *close*, not its
response: response bytes/status reach the client immediately while a
background mirror subrequest to the shadow completes in parallel, bounded
by `mirror_timeout` — test harnesses must read by `Content-Length`, not
read-until-close, or they'll appear to hang.

### 9.3 Rate limiting and traffic shaping (Phase-25)

A leaky-bucket implementation spanning both the stream (root://) and HTTP
(WebDAV/S3) planes, plus bandwidth limiting and a dashboard view. The
directive names (`xrootd_rate_limit_zone`/`_rule`) were deliberately chosen
distinct from the pre-existing Phase-20 per-IP token bucket
(`xrootd_rate_limit`), so the two coexist rather than colliding or one
replacing the other. Two further notable divergences from the original
design doc: the doc assumed an
rbtree+xxhash implementation existed in the repo — it didn't (the existing
KV store uses FNV-1a + open addressing), so Phase-25 built on nginx's
*existing* `ngx_rbtree`+`ngx_slab` machinery (the same approach
`ngx_http_limit_req_module` uses) with an LRU `ngx_queue` for O(1)
eviction. And bandwidth *charging* had to move to a **LOG-phase** handler
using `content_length_n`, not a body filter, because WebDAV's file-serve
path (thread-pool + sendfile) never traverses nginx's chained
`ngx_http_top_body_filter` — a body filter placed there would simply never
run. Stream-plane concurrency limiting (added later as W7) had to treat
the *connection* as the throttled unit rather than the *request*, because
root:// has no per-request teardown event (no LOG phase) the way HTTP
does — a natural, not arbitrary, difference in unit between the two
planes.

### 9.4 Dashboard: config download, anonymous tier, file browser

Config download (`GET /xrootd/api/v1/config`) redacts secrets **fail-closed**
— every directive value is masked unless its name is on a curated
non-secret allowlist; unknown/third-party directives are masked by default,
never revealed by default. The gotcha worth permanently remembering: two
real directives hold live credentials but have names that dodge any
keyword-based redaction heuristic — `xrootd_mirror_token` and
`xrootd_webdav_proxy_auth token <bearer>` — and had to go on an explicit
denylist, because a generic `*token*` substring rule would also incorrectly
mask legitimate non-secret directives like `_token_issuer`/`_audience`/
`_endpoint`. Any future `*_token` directive holding a real credential (as
opposed to an id, endpoint, or path) needs the same explicit denylist
treatment, not a heuristic. An adversarial review before shipping also
caught a heap overflow in the redactor itself: the masked-line output
buffer was sized `input_len*2`, but a masked line actually always writes a
fixed 11-byte token regardless of the original directive's length — many
short directives could overflow it. Fixed with a proven size bound plus a
fail-closed (500 on any doubt) guard. Separately, a validation-methodology
lesson: "checked with curl" is not sufficient proof for anything
cookie/redirect-based — plain `urllib` silently follows a login 302 and
drops the `Set-Cookie` header on the redirect response, so a feature that
looks clean under curl can still be broken under the actual pytest
harness's HTTP client; test with an explicit non-redirect-following opener.

The admin file browser/downloader (2026-06-24) reuses the same
admin-auth-only gate as config download (never the anonymous read tier)
and is confined via kernel `openat2 RESOLVE_BENEATH` to an explicit,
default-empty `xrootd_dashboard_browse_root` — empty means the feature is
off entirely (404s, UI hidden), not "browse everything." A path traversal
attempt surfaces as `EXDEV`/`ELOOP` from the kernel, mapped to a 403.

---

## 10. Monitoring, tap/relay/proxy, and GSI delegation forwarding

The AF-bridging + monitoring stack (2026-06-30) added an address-family
selector for cache-origin connections (`xrootd_cache_origin_family
auto|inet|inet6`), a protocol-agnostic tap/decode core (`src/tap/`, no
nginx dependency), a transparent relay (`src/relay/`), and a revived
`xrootd_tap_proxy*` terminating tap proxy (explicitly *not* the old XCache
proxy it's built from) — plus GSI delegation forwarding through that stack.

The delegation-forwarding root cause is worth recording because it's
genuinely non-obvious and cost several sessions before being found: stock
`XrdSecgsi`'s client only exports its proxy private key / signs a CSR via
`ClientDoPxyreq`, and that code path fires **only** when the client's
*local* flags (`kOptsSigReq`/`kOptsFwdPxy`) are set — which happens only
for a genuine `xrdcp --tpc delegate` operation. Setting the
`XrdSecGSIDELEGPROXY` environment variable alone, which looks like it
should be sufficient and was tried repeatedly, does **nothing** — a red
herring. Separately, proxy certificates need a `keyUsage` extension or
signing fails with a cryptic, unhelpful OpenSSL error. The actual fix was
to PEM-encode the `kXRS_x509_req` bucket at the wire edge (the client had
been parsing a DER-in-PEM-slot as an implicit decline) plus a
proxy-tolerant `check_issued` in `src/crypto/pki_build.c`. Full GSI
tap-proxy forwarding — including hybrid mode against official stock
xrootd and nginx-source/nginx-dest native TPC delegation — is verified
end-to-end. General gotcha for this subsystem: never capture `c->log` for
a sink that's used from a later, decoupled event; keep a stable
`ngx_log_t` copy with `.handler`/`.data`/`.action` all NULL, or the log
context can point at freed connection state.

### 10.1 SciTags flow-label encoding — a real wire-format bug in observability code

The IPv6 Flow Label encoder for SciTags packet marking was emitting a
made-up layout (`(VERSION<<16)|flowid`) instead of the actual IETF-spec
layout (`draft-cc-v6ops-wlcg-flow-label-marking`: 6-bit activity, 9-bit
community/experiment **in reversed bit order**, 5 bits of randomized
entropy at fixed positions). A `scitag.flow=206` flow appeared on the wire
as `65742` instead of the spec-correct `196664` — undecodable by any real
WLCG/CMS monitoring consumer, even though the rest of the pmark stack
(the `scitag.flow` query-string parsing, the firefly UDP reporting of
numeric experiment/activity) was already correct. Verified against
cms-sw/cmssw's own reference implementation before landing the fix — a
reminder that even a purely observational/monitoring feature can carry a
real wire-format bug if its encoding is hand-derived instead of checked
against the actual spec or a reference decoder.

---

## 11. SSI framework and ZIP member access

The XrdSsi unary-echo stub was replaced with a real byte-exact
XrdSsi-over-xroot engine (Tier C), then subsumed by a full 6-phase
framework (session multiplex, async server-push via `kXR_attn`, streaming
responses + alerts, a pure-C CTA protobuf codec with field numbers pinned
from the real CERN gitlab proto files, a flagship CTA tape-service request
queue, and config/metrics). The wire-format lesson repeated here matches
§2's theme: `XrdSsiRRInfo`'s codec byte layout
(`byte0=reqCmd, bytes1-3=reqId BE(24-bit), bytes4-7=reqSize LE`) was wrong
in an early single-request-only implementation that simply ignored
`reqId` — verify wire layouts against a real capture or the actual header,
never intuition, especially for anything touched only by a partial-scope
first pass. Two further wire facts worth keeping for future SSI work: the
response-wait mechanism is `kXR_query infotype=kXR_Qopaque` (opaque type
64), and the `libXrdSsi` client requires the open reply to append a
StatInfo string after the 12-byte `ServerOpenBody`, or the client refuses
the open.

ZIP member access (Phase-57 W2) shipped in three passes across three
protocols: root:// (stored members, then raw-inflate deflate support using
`windowBits=-15` — codec_core's zlib-wrapped DEFLATE would fail against raw
ZIP data), then WebDAV GET, then S3 GET, with the WebDAV and S3 handlers
ultimately refactored to share one `src/zip/zip_http.{c,h}` implementation.
The finding that reprioritized this work: the **stock/native XrdCl client
already does `xrdcl.unzip` entirely client-side** (opens the archive, reads
the central directory and member bytes itself, inflates locally) — verified
by watching the access log show only whole-archive opens and partial reads,
never a server-side member request. So the root:// server-side member path
mainly serves raw/non-plugin clients; the actually high-value surface is
HTTP/WebDAV/S3, where clients have no ability to self-inflate a ZIP
central directory — which is exactly the surface that got built out fully.

---

## 12. Pelican/OSDF federation

Checksum-on-fill integrity plus broad HTTPS/Pelican-origin support for the
read-through cache landed in three phases: verify-before-persist (any
completed cache fill's digest is checked against the origin's before the
atomic rename, policy `off`/`best-effort`/`require`, default fail-closed
`best-effort`); a generic HTTP(S) origin transport (libcurl, follows
redirects, captures RFC 3230 `Digest`); and Pelican federation *pull*
(fetch `.well-known/pelican-configuration`, extract `director_endpoint`,
follow the director's 307 redirect to the actual origin).

*Registering* this node as a discoverable Pelican cache (phase 3b, the
push direction) is implemented — a periodic signed `OriginAdvertiseV2` POST
to the director, using a newly-added ES256 JWT **minting** capability
(`xrootd_jwt_sign_es256`, the module's first and only signing path — it
previously only *verified* tokens) — but has an explicit, load-bearing
prerequisite that is **not** implemented: registering this cache's public
key with the federation registry, which today requires an operator running
the `pelican` CLI out-of-band. Without that registration, the director
cannot verify the advertise JWT this code sends, so the feature is real
but inert until that manual step happens. Also explicitly not done: serving
a JWKS endpoint, and a signed/verify roundtrip self-test for the new
signing path (deliberately deferred under "implement before testing," i.e.
the mint path was written but never exercised against the verify path in
the same session).

---

## 13. Where the module stands vs. stock XRootD (2026-06-26 audit)

A 12-domain, 149-feature-point comparison against `/tmp/xrootd-src`
concluded: nginx-xrootd is a high-quality reimplementation of the XRootD
**protocols**, not a drop-in replacement for the XRootD **platform** — the
remaining gap is architectural, not a punch-list of small fixes. The wire
protocol itself is essentially complete (opcodes 3000–3032 implemented
except the deprecated `kXR_gpfile`).

**Drop-in-ready for:** POSIX disk gateways over root:///roots:// with
single-stream XrdCl; WebDAV+token sites (davs://) — where it *exceeds*
stock XrdHttp; full server-side S3 (stock XRootD has no S3 server at all);
single-tier CMS redirectors with disjoint path prefixes; space accounting
via the SRR endpoint + Prometheus.

**Not drop-in for:** Tier-1/tape sites; non-POSIX backends (Ceph/EC/
object/HDFS); the WLCG binary UDP monitoring fabric; multi-stream XrdCl
(`pathid`); plugin-driven sites; I/O-load-fairness pools.

**Three architectural blockers, deliberately never fixed by small patches:**

1. **No OSS backend abstraction** — the filesystem layer called
   `open`/`openat2` directly with no indirection, so no non-POSIX backend
   (Ceph, object storage) was possible, and XRootD's C++ `.so` plugins
   can't be hosted in a C module regardless. (Later closed by the
   storage-driver abstraction — phases 55/56, see
   `lessons-migration-era-2026.md` §0/§2.)
2. **No real FRM/tape staging** — `prepare_cmd.c` was fire-and-forget
   fork/exec with a hardcoded reqid, no cancel/evict, no `kXR_offline`.
   (Later addressed by the FRM dissolution into `fs/xfer/` + `sd_frm` —
   `lessons-migration-era-2026.md` §4 — though full migrate/purge remains
   an intentionally scoped-out capability, delegated to MSS/operator.)
3. **No plugin loader / `xrootd.cf` config compatibility** — not
   `xrootd.cf`-compatible; only one fixed dlopen target
   (`libvomsapi`); no `fslib`/`osslib`/`authlib`/`namelib` N2N mechanism.
   Considered structurally impossible to fully close in nginx; a
   cf-translator plus native N2N (`localroot`/`remoteroot`) was scoped as
   the feasible subset.

**Where nginx-xrootd exceeds stock:** server-side S3 (stock is client-only,
~6900 LoC here); WebDAV class-2 LOCK/UNLOCK + PROPPATCH (stock's XrdHttp is
DAV:1 only); HTTP-TPC OIDC delegation + RFC 8693 token exchange; macaroon
issue+verify; identity-aware leaky-bucket rate limiting (stock's
`XrdThrottle` is username-only); OCSP+stapling; native SHA-1/SHA-256 (no
`ckslib` dependency); Prometheus/dashboard/SRR observability.

Quick-win items identified but not necessarily all landed by this audit's
date: `?authz=` bearer-token query param (used by davix/gfal2/xrdcp, but
this module only read the `Authorization` header), classic macaroon POST
content-type, `XrdCks` binary checksum-xattr interop (text vs binary
format), and multi-stream `pathid` response routing. Binary UDP f/g-stream
monitoring was explicitly **rejected by Rob** as a blocker to chase — the
SRR endpoint covers space accounting, not transfer accounting, and that
distinction was judged sufficient.

---

## 14. Consolidated gotchas quick-reference

A grep-able summary of the recurring, non-obvious traps this era's work
kept hitting — most already have their own subsection above; this table is
for fast lookup.

| Gotcha | Where it bites | Fix/mitigation |
|---|---|---|
| `struct` field added to `context.h`/`file.h`/`config.h` | Any phase touching per-connection or per-file state | Full `rm -rf objs && ./configure ... && make` — never trust incremental `make` across a struct-layout change (mixed-ABI SIGSEGV, not a link error) |
| `REPO=path ./configure --add-module=$REPO` | Any fresh configure invocation | `$REPO` expands empty in the parent shell before the command runs — use the literal absolute path |
| New `.c` file added to a phase | Any phase adding files | Register in the top-level `./config` (`$ngx_addon_dir/src/...` list), not `config.h`; then re-run `./configure`, not just `make` |
| S3 shared port 9001 restart | Any S3 phase's manual dev-loop restart | Must restart with `-p /tmp/xrd-test -c conf/nginx.conf` (prefix form) — dropping `-p` binds the wrong prefix and the stale master silently keeps serving old code |
| `ngx_log_debug*` calls | Any test relying on debug-level log lines | Compiled out entirely without `--with-debug` — assert on observable behavior (timing, counters), not debug-line presence/count |
| Loopback `connect()` to a not-yet-listening port | CMS mesh boot-race debugging | Returns `EINPROGRESS`, not an immediate refusal — the refusal only surfaces later via `recv()` |
| `xrootd_http_set_header()` | Any code emitting a header name from a reused/stack buffer | Copies the *value* but stores the header-name pointer uncopied — allocate the name from `r->pool` per emission or later-emitted headers corrupt earlier ones |
| `xrootd_sha256()` return convention | Any new caller | Returns 1 = success (OpenSSL convention), not 0 — easy to invert by assumption |
| `ngx_snprintf` | Any code building a C string for %s reuse | Does not NUL-terminate — must write `'\0'` explicitly after each use |
| A "done" async/offload code path | Any phase adding a thread-pool offload | Prove it's actually reached (strace the worker TIDs, not just the main thread) before trusting its correctness — S3's offload sat unreachable for an entire phase (§7.3) |
| `perf record -m` | Any flame-graph profiling session | Exceeds `perf_event_mlock_kb` under the worker fleet's memory division — omit `-m` |
| nginx core's `ngx_http_header_filter_module` | Registering a new HTTP header/body filter from a module's preconfiguration | It clobbers `ngx_http_top_header_filter` via direct assignment regardless of registration order, so a filter registered the normal way silently never fires — this is why WebDAV's header filter lives in a separate `HTTP_AUX_FILTER` module (`src/webdav/xrdhttp_filter.c`) instead |
| Starting the nginx binary after a phase-46-era rebuild | Any manual dev-loop restart on this host | Needs `LD_LIBRARY_PATH=/tmp/rt_libshim:/usr/lib64` — the binary's `DT_NEEDED` wants `libbz2.so.1.0` but the system only ships `libbz2.so.1`; a shim symlink resolves it |
| Proving a thread-pool offload path actually ran | Any phase adding/verifying async offload (see S3 §7.3) | `strace` every worker thread TID, not just the main thread — offload can look "done" while silently still running synchronously on the event loop |
| `module_core_directives.c` | Adding a new **stream**-plane directive | Contains a duplicate stream-directive table that is not wired into `./config` — new stream directives must go into `src/stream/module.c`'s `ngx_stream_xrootd_commands[]` instead, or they're silently dead |

---

## 15. Open / deferred items carried out of this era

| Item | Class | Notes |
|---|---|---|
| Phase-29 P3: AIO read pipelining (decouple reads from `XRD_ST_AIO`) | perf, deferred | Disconnect-mid-AIO UAF guard unexercisable in current env; needs a working disconnect-mid-AIO test before resuming |
| Phase-32 WS3: concurrent-AIO recv-state-machine flip | perf, deferred | Foundation (pool + inflight/backpressure fields) landed; the actual flip needs a real perf host + a non-flaky harness |
| Phase-33 P1: `PIPELINE_MAX` raise + the WS3 flip | perf, deferred | Explicitly the highest-leverage remaining throughput work; blocked on P0 (a trustworthy perf host — WSL2 is not one) |
| S3 W4: offload spooled/aws-chunked/MPU writes further | perf, deferred | Event-loop UAF risk; only measurable on real hardware |
| S3 listing pagination walk-cursor cache | perf, deferred | Marginal value vs. cross-request cache complexity |
| S3 HEAD checksum-open avoidance | perf, deferred | Blocked on either dropping the default crc64nvme echo (a visible wire behavior change) or a correctness-risky residency-gating refactor |
| Memory-budget streaming W2.3: full *resident* windowing of `readv`'s interleaved `[seghdr][data]` layout | perf/correctness, deferred | Higher risk, lower frequency than the landed W1/W2.1; `pgread` windowing is separately blocked on its `kXR_status`/per-page CRC framing and stays budget-bounded rather than windowed |
| CTA tape-service tier/frm wiring | correctness, deferred | The flagship CTA request queue (§11) has only test-executor wiring; real tier/FRM wiring is left TODO |
| Phase-57 write mirroring W3 (stream data writes) | correctness, deferred | Implemented and build-clean but end-to-end runtime validation + ASAN never completed — required before enabling in production |
| WebDAV lock shared-lock coexistence (Phase-57 W3.3.b) | correctness, deferred | 2nd shared LOCK still returns 423; optional |
| Pelican cache-registration handshake (public-key registration with the federation registry) | integration, blocked on operator action | The `pelican` CLI step is out-of-process; the advertise JWT this module sends is unverifiable by the director without it |
| Pelican JWKS endpoint + sign/verify roundtrip self-test | correctness, deferred | New ES256 signing path was never exercised end-to-end against the existing verify path |
| kTLS engagement demonstration | verification, blocked on hardware | This WSL2 6.18.6 kernel's kTLS TX is broken and the build lacks `NGX_HAVE_OPENSSL_SSL_SENDFILE`; "default ON" needs re-verification on a mainline kernel |
| CNS (cluster namespace) v1 limitations | scoped, by design | In-memory per-worker only (correct only for `worker_processes 1` on a manager); only `closew` emits inventory events; unknown-path stat returns `kXR_wait` not `kXR_error` |
| chkpoint `kXR_ckpXeq` wire framing | **closed** — listed here only to correct the record | Was open per `lessons-migration-era-2026.md` §9.4 at time of writing; closed the same day (§2.2 above) |
| Multi-stream `pathid` response routing | feature gap, feasible-but-unscheduled | `ClientReadRequest` wire struct lacks a `pathid` field entirely; the read handler parses only fhandle/offset |
| Binary UDP f/g-stream transfer monitoring | rejected, not a gap | Explicit product decision (Rob) — SRR covers space accounting, not transfer accounting, and that's judged sufficient |

---

*No memory file reviewed for this document was empty of durable content;
all ~50 contributed at least one decision, incident, or gotcha retained
above. Several (e.g. `phase4_op_descriptors`, `phase6_status`,
`phase9_s3_sigv4`, `phase10_dashboard_jansson`, `phase12_shared_file_serve`,
`phase21_subrequests_filters`) were narrow "verified complete, dead code
removed" audits — their lasting value was mainly the dead-code removals and
the doc-vs-code divergence notes, which are folded into the phase table in
§1 rather than given their own sections.*
