# Phase 61 — CMS parity: close the remaining cmsd gaps

**Status:** COMPLETE 2026-07-27 — **PR-1…PR-8 DONE via
`phase-89-design-backlog-burndown.md` §C** (per-PR record + deviations from
this spec live there; full CMS gate 72 green), and the **W7 remainder LANDED
2026-07-27** (block below) — the phase-62 split of ADR-4 was not needed at the
scoped size. This doc is now the design-of-record / rationale; where the two
disagree, the phase-89 DONE entries and the LANDED block are the truth
(notably W8: per-worker deadline-window aggregation shipped instead of App
C.2's SHM agg table, and W6′ blacklist-file polls the ping tick, not the
health-check timer).

## LANDED — W7 remainder (2026-07-27, UNCOMMITTED)

Four PRs close the last two open cells of E.1 (full `stats` XML + multi-tier
roles/recursion). All wire facts were re-verified against upstream v5.9.6
sources (`YProtocol.hh`, `XrdCmsNode.cc`, `XrdCmsRouting.cc`,
`XrdCmsCluster.cc`) before coding. Suite: `test_cms_wire_pup_conformance.py`
49/49 green (10 new tests + a 6-test hardening pass: server-role Mode word,
supervisor `mkdir` fan-down (`cms_super_fan_down`) with local-non-exec,
supVOps `update` drop, and the relay trust anchor's three properties —
forged-path-no-consume, single-use entries, no loc_cache poisoning by dropped
unsolicited HAVEs); neighbouring HAVE/locate/affinity suites 18/18.

**Hostile-network / MITM conformance (`test_cms_hostile_conformance.py`, 5256
green).** brix is designed to sit as a CMSD man-in-the-middle between a trusted
site cluster and an untrusted remote cluster; this suite proves it stays solid
with a hostile peer on *either* leg, and — the headline property — that abuse
on one leg never stalls the other (where stock cmsd↔cmsd would head-of-line
block or black-hole). Coverage:
- **Server (accept) leg** — a garbage/0xFF flood, an oversized frame
  (dlen+8 > 4096), a truncated-header hangup, and connection churn each close
  only the offender while a fresh client is still served; the dlen boundary
  (4088 accepted vs 4089 rejected) is pinned; unknown opcodes and empty
  `kYR_state` are dropped without closing; pre-login LOAD/AVAIL/STATFS/STATUS/
  USAGE are silently gated yet the connection survives (proven by header-only
  `kYR_ping`→`kYR_pong`, which needs no login); a 200-frame ping flood crosses
  the 64/wakeup fairness yield without dropping the connection.
- **Node (dial-out) leg** — an oversized frame or `kYR_disc` from a hostile
  manager forces a *clean* reconnect (fresh LOGIN) rather than mis-framing;
  in-frame garbage opcodes and malformed forwarded rrdata are tolerated
  (dropped, no reconnect); a `..` traversal `kYR_state` yields no `kYR_have`;
  ping floods keep the node answering.
- **MITM cross-leg isolation** — an outstanding (never-answered) relay entry
  does not block the upward leg's ping; a hostile child flooding the downward
  leg cannot wedge the upward manager leg; relay-table saturation (>64 parked
  probes) fails closed; new children still register under relay pressure; a
  child answering after the 5s relay TTL is refused (no forged upward HAVE).
Liveness oracle throughout: `kYR_ping`→`kYR_pong` (server leg needs no login),
plus re-LOGIN detection for node-leg reconnects.

The suite was then extended (+32, → 54 green) to the *esoteric* ops a hostile
peer can throw at the less-travelled handlers:
- **Server-leg esoterica** — out-of-sequence `kYR_xauth` (no sss challenge
  outstanding) closes only the offender; `kYR_stats` is gated pre-login yet the
  connection lives, and post-login returns the `[4B statsz][role XML]` doc
  (size-form floodable); `kYR_gone` for an unheld or over-long path is a bounded
  no-op; a self-driven `kYR_status` suspend→reset→resume and any garbage
  modifier never drop the link; `kYR_usage`→`kYR_load`; a `kYR_error` fan-out
  fold with a 2 KB peer text is length-bounded and a sub-`ecode` short payload
  is safe; an unsolicited `kYR_pong` and a foreign-export `kYR_have` are both
  ignored without disturbing the connection.
- **Node-leg esoterica (MITM-critical)** — an unsolicited `kYR_select`/`kYR_try`
  naming an attacker host:port for a stream with no pending locate steers
  *nothing* (redirect-injection defeated); a truncated (<3 B) or port-overrunning
  redirect is refused without over-read; a manager `kYR_status` suspend/resume
  (and garbage modifier) leaves liveness intact; `kYR_space`/`kYR_stats`/
  `kYR_update` are answered (`kYR_avail`/`kYR_data`/`kYR_status`); every
  forwarded namespace opcode (chmod/mkdir/mkpath/mv/rm/rmdir/trunc) and both
  prepare opcodes fed truncated Pup rrdata are dropped/`kYR_error`'d with no
  reconnect; the dir-shaped forwarded ops with a `..` escape are refused by the
  kernel-confined open (nothing created outside the export root).
- **Wire-level hardening (both legs)** — a byte-dribbled frame is reassembled;
  a 200-frame zero-dlen unknown flood, an interleaved valid+garbage+valid
  sequence, and a full 0–255 modifier-byte sweep across `kYR_status`/`kYR_stats`
  never crash or lose frame alignment; an extreme `0xFFFFFFFF` streamid is
  parsed without a signedness bug (stock static streamid-0 pong); a slowloris
  partial-LOGIN holds only its own slot (a fresh client is served immediately)
  and is reaped by the absolute 10 s login deadline.
A final deep pass (+8, → 62 green) reaches the handlers a fuzzer hits last,
half-open teardown, and the headline property under *concurrent* abuse:
- **Auth / namespace / statfs esoterica** — a malformed `kYR_login`
  (unparseable `CmsLoginData`) closes only the offender (XrdCmsLogin::Admit
  parity) while a fresh client is still admitted; a `kYR_statfs` with
  unparseable Pup rrdata or with no path field draws no `kYR_data` (reject, not
  NULL-deref) and the connection recovers to answer a valid statfs; a `kYR_have`
  whose path holds `..` or is non-absolute is dropped by the same reject-shaping
  as the state ingest (cannot poke the loc cache); a `kYR_cns` namespace event
  pre-login / collect-off is a silent no-op.
- **Half-open teardown** — a peer that announces a large dlen, sends a fraction
  of the body, then hard-resets makes the accumulator hit EOF on a partial frame
  and clean up without wedging; a fresh client is served immediately.
- **Concurrent cross-leg isolation (headline)** — a background thread saturates
  the supervisor's downward accept leg with an endless garbage-frame torrent
  while the upward manager leg is pinged in a loop: every upward ping is
  answered throughout, and once the flood stops the accept leg still admits a
  well-behaved child.  Neither leg can be starved by sustained abuse of the
  other — the exact stock cmsd↔cmsd failure this MITM design exists to remove.
A role-confusion pass (+5, → 67 green) covers the classic stock cmsd↔cmsd
trouble spot — a peer replaying the *other* leg's opcodes:
- **Wrong-direction opcodes** — a logged-in node emitting node-role ops it should
  only ever RECEIVE (`select`/`try`/`state`/the forwarded-namespace set) has each
  dropped by the manager route table with no mis-dispatch; symmetrically a
  hostile manager emitting server-role ops (`statfs`/`gone`/`have`/`usage`/`load`/
  `avail`/`cns`/`xauth`) at a node is dropped with no reconnect.  Neither peer can
  push a frame into the wrong state machine.
- **`kYR_disc` handshake** — a node's disconnect is echoed (`do_Disc` parity) and
  that link closed cleanly while every other client keeps being served.
- **`kYR_status(stage)`↔`(nostage)`** — the disk-only↔staging capability
  transition a real node makes leaves the registration intact.
- **Multi-host `kYR_try` injection** — an ordered *list* of attacker redirect
  targets for a stream with no pending locate steers nothing (the node can't be
  walked through an attacker's redirect chain for a request it never issued).
A byte-level parser pass (+10, → 77 green) fuzzes the numeric field decoders,
login edge cases, zero-payload safety, and the fairness-batch boundary:
- **Numeric parsers** — a `kYR_load` advertising the maximal `0xFFFFFFFF` free-MB
  is decoded by the bounded TLV reader without overflow and the statfs encoder
  handles the extreme aggregate; a truncated `kYR_load`/`kYR_avail` decodes
  missing fields as zero (documented posture) without an over-read, and a
  following well-formed `kYR_avail` restores a real figure (no latched bad
  value).
- **LOGIN edge cases** — an empty Paths list is a valid registration; a Paths
  list exceeding the 1 KB `ctx->paths` buffer (but within one frame) is truncated
  under the `dst_end` guard, never overflowed; an all-bits Mode word is
  classified by the Admit role bits without crashing; a `..` export declaration
  is copied bounded and grants no escape (a later foreign `kYR_have` is still
  dropped — confinement is enforced at the have/statfs/forward gates, not the
  export string).
- **Zero-payload safety** — every payload-bearing op on both legs fed an empty
  body is handled without a short read (server ops stay serviceable; node ops
  drop/`error` with no reconnect).
- **Fairness-batch boundary** — exactly 64 ping frames (one full 64/wakeup
  batch) followed by a 65th split across the wakeup boundary yields all 65
  pongs: no frame dropped at the batch edge, trailing partial reassembled next
  wakeup.
Gotchas locked in by fixing wrong first-draft asserts: the server-leg `kYR_pong`
carries a fixed **streamid 0** (stock `CmsPongRequest`), so pong replies are
identified by code+empty-payload, never by streamid echo (`kYR_load`/`kYR_avail`
DO echo the streamid); `kYR_status(reset)` legitimately zeroes cached free-space,
so esoteric tests assert *liveness* (ping/pong, statfs-answers) after any
state-mutating op rather than a specific space figure.  Two more: statfs `wFree`
is the **table-wide** aggregate (`brix_srv_aggregate_space`, not path-filtered),
so an empty-Paths login leaves `wFree` unchanged — only the path-match count
goes to zero; and an oversized-Paths login test must keep the whole LOGIN frame
under the 4 KB `MAX_FRAME` (else it trips the oversized-frame close, a *different*
defense) while exceeding the 1 KB `BRIX_SRV_MAX_PATHS` buffer to exercise the
`dst_end`-guarded copy.

A node-leg STATE-probe + relay-depth pass (+9, → 86 green) drives the MITM
*downward* direction — the confined existence probe and the multi-tier relay
that parks a parent's `kYR_state` while re-asking children:
- **Confined existence probe (data node)** — a positive control pins that a
  `kYR_state` for the genuinely resident export file DOES draw a `kYR_have`, so
  the negatives are confinement rather than a dead probe: a probe for a real
  host file *outside* the export root (`/etc/passwd`) draws no `kYR_have`
  (`brix_stat_beneath` + `RESOLVE_BENEATH`); a ~1 KB-plus path (over the 1 KB
  `pathz` buffer, under the frame limit) is rejected by `cms_state_extract_path`
  with no over-read; a relative (non-`/`) path and an empty (`pl==0`) path are
  rejected; an embedded-NUL path (`/have_me.bin\0/etc/passwd\0`) truncates at
  the first NUL to the resident prefix, so the trailing foreign bytes are never
  read as a path.
- **Relay single-use / path-binding (supervisor)** — `take()` consumes a parked
  entry only on an *exact* path match on the issued down-streamid: a child
  answering the right down_sid with the WRONG path is refused *and* the entry
  survives, so the child's later honest answer for the probed path still lands
  the upward `kYR_have` (the forged answer cannot self-inflict a DoS on the
  honest reply); a *replayed* honest answer finds the entry already cleared and
  is dropped (no duplicate upward HAVE); an unsolicited HAVE carrying a
  never-issued down_sid matches no entry and is then dropped by paths-cover — a
  hostile child can assert only a path this manager actively probed, once,
  within the TTL, on the exact streamid it issued.

An accept-leg resilience-limits pass (+4, → 90 green, dedicated hardened
template with the Phase-50/A3 knobs turned down to test-observable values)
proves the deadlines + admission caps + non-blocking write path that stop the
"hostile network hang" classes stock cmsd↔cmsd is weakest on:
- **Idle watchdog** — a node that completes LOGIN then goes completely silent
  is closed by the post-login idle watchdog (3 s here) so a hostile peer cannot
  register and then hold a registry slot forever; a fresh client is still
  served.  (Template gotcha locked in: `brix_cms_server_idle_timeout` is an
  `ngx_conf_set_msec_slot` directive, so a bare integer is read as **seconds** —
  the value needs an explicit `3s`/`3000ms` unit or the watchdog silently sits
  at ~50 min.)
- **Per-IP admission cap** — 20 simultaneous connections from one source IP
  against a per-IP cap of 8: at most 8 are admitted and serviced, the overflow
  is refused (`ngx_stream_finalize_session(FORBIDDEN)` at accept, before any
  frame handler), and service resumes once the held connections are released.
  One hostile IP cannot exhaust the accept leg (`cms_cap_rejections_total`).
- **Slow / zero-reading peer (write backpressure)** — the canonical wedge: a
  peer floods `kYR_ping` but never reads the `kYR_pong` replies, so its receive
  buffer and the server's send buffer fill.  `brix_cms_send_all` returns
  `NGX_AGAIN` and the frame is dropped rather than blocking, so the single
  worker keeps serving a separate well-behaved peer — where a blocking-write
  cmsd would stall every client behind the slow reader.
- **Half-close (SHUT_WR)** — a peer that shuts its write half (FIN) while
  keeping its read half open (a real asymmetric-network teardown) is seen as
  EOF on the read side and torn down cleanly; other clients keep being served.

Large-scale opcode / frame-size / state-path sweeps (+159, → **249 green**)
carpet-bomb both legs, re-proving liveness after every single hostile frame on
one long-lived instance per leg (so a slow resource or state leak across
hundreds of frames surfaces as a late red).  Four parametrized classes:
- **`TestServerLegOpcodeMatrix` (72)** — every rrCode a stock cmsd defines
  (minus LOGIN/PING) plus a band of raw unknowns (36), each with a garbage
  payload, once **pre-login** (pre-auth gate) and once **post-login** (per-op
  handler live).  The offending frame may cost the offender its connection
  (DISC/malformed/out-of-seq-XAUTH close it); a *fresh* client always still
  gets its `kYR_pong`.
- **`TestFrameSizeBoundarySweep` (23)** — the exact dlen boundary: 16 accepted
  dlens (`{0,1,…,4086,4087,4088}`, total `dlen+8 ≤ 4096`) are read-and-dropped
  in full behind an unknown opcode with the same connection then answering a
  `kYR_ping` (framer alignment preserved), and 7 rejected dlens
  (`{4089,…,65535}`, `dlen+8 > 4096`) close the offender on the length word
  (header-only send, before any body) while the accept leg stays up.
- **`TestNodeLegOpcodeMatrix` (36)** — every opcode + garbage thrown by a
  hostile manager DOWN into the node; the upward leg keeps answering `kYR_ping`,
  tolerating a DISC-forced reconnect (the `_node_survives` oracle retries
  through the reconnect window).
- **`TestNodeStatePathCorpus` (28)** — a broad adversarial `kYR_state` corpus
  (parent-traversal, non-absolute, absolute-outside-export, control-byte,
  oversized, near-miss) each drawing **no** `kYR_have` from a data node whose
  only resident file is `/have_me.bin` — `cms_state_extract_path` rejects
  `..`/relative/oversized before any syscall and `brix_stat_beneath` +
  `RESOLVE_BENEATH` confines the rest.

Two module-scoped fixtures (`sweep_server`, `sweep_node`) boot one instance per
leg on a dedicated `LifecycleHarness` (ledger ports `lc-cms-hostile-sweep-srv`
30420 / `lc-cms-hostile-sweep-node` 30421) so the whole barrage runs against a
single long-lived process.

A second deep-fuzz wave (+314, → **563 green**) widens the header/parser/corpus
axes on the same two sweep instances:
- **`TestServerModifierByteSweep` (96)** — every low-6-bit `kYR_status` modifier
  (64, on one shared logged-in link, each re-proving the link stays frame-
  aligned and answers a ping) and every low `kYR_stats` modifier (32) — the
  header modifier byte can never desync the framer or crash the encoder.
- **`TestServerStreamidSweep` (24)** — a ping at each adversarial streamid
  (0/1/`0x7FFFFFFF`/`0x80000000`/`0xFFFFFFFF`/…) is parsed as the unsigned wire
  value, no signedness/truncation bug.
- **`TestServerFragmentationSweep` (16)** — a junk-frame+ping composite split at
  every interesting byte offset always drops the junk and reassembles the ping
  across the `recv()` edge.
- **`TestServerPipeliningSweep` (19)** — N back-to-back pings (N up to 512,
  spanning the 64-per-wakeup fairness batch) draw *exactly* N pongs; no frame
  dropped at the batch edge.
- **`TestServerLoginFuzzSweep` (30)** — a broad malformed-`CmsLoginData` corpus
  (empty, truncated at each TLV boundary, bad tags, oversized) may cost the
  offender its connection but never wedges the worker: a fresh client is served.
- **`TestServerLoadAvailTlvFuzzSweep` (24)** — the bounded load/avail TLV reader
  fed truncated/garbage/oversized-count payloads decodes missing fields as zero
  and never over-reads; the same link answers a ping after each.
- **`TestNodeForwardedOpFuzzSweep` (45)** — every forwarded namespace opcode
  (chmod/mkdir/mkpath/mv/rm/rmdir/trunc/prepadd/prepdel) × 5 payload variants
  (empty/truncated-Pup/garbage/`..`-traversal/embedded-NUL) — none crashes,
  wedges, or forces the node to **hang up** (login count unchanged), upward leg
  still answering.
- **`TestNodeRedirectInjectionSweep` (32)** — unsolicited `kYR_select`/`kYR_try`
  × 16 host-list payloads (empty, no-NUL, oversized host, 50-host list, bad
  port, embedded NUL, non-ASCII) for a streamid with no pending locate steer
  nothing and never make the node hang up.
- **`TestNodeStatePathCorpusExtended` (28)** — a second disjoint adversarial
  `kYR_state` corpus (`/proc`, `/dev`, `/sys`, secrets, UTF-8, oversized-in-
  buffer, near-miss, `..`-to-resident) each drawing NO `kYR_have`.

A third exhaustive-fuzz wave (+469, → **1032 green**) carpet-bombs the modifier,
streamid, login-value, ingest, forwarded-op, resync and concurrency axes, again
on the same two long-lived sweep instances (server-leg classes first, node-leg
classes appended LAST so `sweep_node` is never mid-DISC-reconnect when they run):
- **`TestServerOpModifierMatrix` (144)** — each body-carrying accept-leg opcode
  (`state`/`have`/`load`/`avail`/`gone`/`status`), empty-bodied, × 24 modifier
  bytes (every low nibble, the 0x40 flag band, the 0x80 raw-form bit, 0xE0..0xFF)
  on one shared logged-in link; the modifier byte can never desync the framer nor
  gate a close — the same link answers a ping after every case.
- **`TestServerLoginModeWordSweep` (24)** — a structurally valid login carrying
  each esoteric 32-bit role/mode word (single bits, flag combos, sign boundary,
  `0xFFFFFFFF`) always registers a HEALTHY link (classifier never half-opens).
- **`TestServerLoginPortSweep` (16)** — a login advertising each edge data port
  (0-adjacent, 65535, 32768, …) never wedges the accept leg for other peers.
- **`TestServerLoginPathListCorpus` (24)** — every edge/hostile export
  declaration (empty, `..`, embedded-NUL/space/tab, 100-entry list, no-flag,
  400-byte single path) is copied bounded, no escape, no wedge.
- **`TestServerHaveIngestFuzz` (30)** — adversarial `kYR_have` advertisements
  (foreign/covered/traversal/`/proc` paths × online/pending/raw/0/0xFF modifiers)
  are dropped by the paths-cover gate (relay-take finds no entry) without
  desyncing the link.
- **`TestServerGonePathCorpus` (24)** — a `kYR_gone` for each adversarial path
  (foreign, `..`-chains, `/proc`, embedded-NUL, 300-byte, non-ASCII) is a bounded
  no-op that keeps the link aligned.
- **`TestServerErrorFrameCorpus` (24)** — a received `kYR_error` with each ecode
  × text length (0..3000 bytes) is consumed exactly, never over-read.
- **`TestServerInterleaveResyncMatrix` (34)** — ping / one arbitrary opcode+body
  / ping on a fresh conn: the second pong proves the accumulator resynced past
  the interposed frame for every opcode (DISC/XAUTH excluded — they legitimately
  close the offender).
- **`TestServerConcurrentStormMatrix` (18)** — 6 attacks (garbage flood,
  oversized frame, zero-dlen flood, 2000-ping flood, half-open, dangling-header)
  × concurrency {2,4,8}: a fresh honest client is still admitted and answered
  while the storm is open — the headline HOL-block failure this MITM removes.
- **`TestNodeOpModifierMatrix` (72)** — each manager-leg opcode
  (`state`/`have`/`load`/`avail`/`status`/`space`), empty-bodied, × 12 modifier
  bytes DOWN into the node; the upward leg survives (reconnecting if it must).
- **`TestNodeStreamidSweep` (24)** — a ping DOWN at each adversarial streamid;
  the node parses the unsigned word and keeps its upward leg alive.
- **`TestNodeDownwardFloodMatrix` (35)** — a 120-frame downward flood of each
  opcode (garbage-bodied, DISC excluded) never wedges the node's upward leg — the
  manager ping is answered after the barrage (through a forced reconnect if any).

A fourth full-byte wave (+1280, → **2312 green**) drives the modifier and opcode
bytes across their *entire* 0..255 range on both legs — the exhaustive
generalisation of the sampled matrices above, proving no single byte value
(however undefined) can desync the framer, crash a handler, or hang up the proxy:
- **`TestServerStatusFullModifierSweep` (256)** — `kYR_status` across every
  modifier byte on one logged-in link; the suspend/resume/reset/stage state
  machine and every undefined bit combination keep the link answering a ping.
- **`TestServerStateFullModifierSweep` (256)** — empty-bodied `kYR_state` across
  every modifier byte; the 0x80 raw-form bit and all others select a parse form
  but an empty body is always dropped without closing the link.
- **`TestServerHaveFullModifierSweep` (256)** — `kYR_have` for a foreign path
  across every online/pending/raw bit combination; paths-cover drops each without
  desyncing the link.
- **`TestServerFullOpcodeByteSweep` (256)** — every rrCode byte 0..255,
  garbage-bodied, pre-login: the offender may be closed but a fresh client is
  always served (no opcode byte takes the worker down).
- **`TestNodeStateFullModifierSweep` (256)** — empty `kYR_state` DOWN into the
  node across every modifier byte; the upward leg survives every one.

A fifth wave (+2944, → **5256 green**) carries the full-byte modifier sweep across
every remaining silent op and adds fine-grained length / depth / streamid sweeps:
- **`TestServerLoad/Avail/GoneFullModifierSweep` (3×256)** — the remaining silent
  accept-leg ops (`kYR_load`/`kYR_avail`/`kYR_gone`) empty-bodied across every
  modifier byte on a shared logged-in link; each a bounded no-op, link aligned.
- **`TestServerStatePayloadLengthSweep` (256)** — `kYR_state` carrying a foreign
  path truncated to every body length 0..255: the path-length decode boundary is
  exercised finely, every length dropped without desyncing the link.
- **`TestServerFrameSizeFineSweep` (256)** — an unknown-opcode frame at every body
  length 0..255 is read-in-full and dropped, connection intact.
- **`TestServerStreamidDenseSweep` (256)** — a ping at 256 densely-spread
  streamids (`0x00000000`…`0xFFFFFFFF`) always answered.
- **`TestServerPipeliningFineSweep` (128)** — every pipeline depth 1..128 draws
  *exactly* that many pongs across the 64-per-wakeup fairness edge.
- **`TestNodeStatus/Have/Load/AvailFullModifierSweep` (4×256)** and
  **`TestNodeOpcodeByteFullSweep` (256)** — the full-byte modifier sweep for every
  manager-leg op DOWN into the node, plus every rrCode byte 0..255 garbage-bodied
  down; the node's upward leg survives every case (reconnecting only if forced).

As part of this wave `test_zero_payload_all_node_ops_safe` was hardened from a
strict `LOGIN-count == base` reconnect assertion (which could flake on a single
*incidental* dial-out re-dial under load / the WSL2 backward-clock-step) to
tolerate ≤1 incidental reconnect while still catching a per-op reconnect storm —
the "assert robust liveness, never a fragile count" discipline applied to a
pre-existing case surfaced only under the full 5256-test serial run.

**PR-A — full `stats` reply (both legs).** `kYR_stats` without `kYR_size` now
returns `[4B BE statsz][Cluster.Stats XML]` where the doc is byte-exact stock
`statfmt1` = `<stats id="cms"><role>%s</role></stats>` and statsz keeps the
stock advertisement 48 (`sizeof(statfmt1)+8`); size form unchanged. Role
strings per stock: `MM`/`M`/`R`/`S`.

**PR-B — `brix_cms_role` (auto|server|manager|supervisor).** Login Mode words
per stock Pander: server→`kYR_server` (0x08), manager→`kYR_manager` (0x02),
supervisor→`kYR_manager|kYR_server` (0x0A); auto keeps the legacy
`0x08 | (manager_mode ? 0x02 : 0)`. An explicit role also installs the stock
inbound valid-ops table on the upward leg (`router.c`): manVOps
(`initMANrouting`) for manager, supVOps (`initSUProuting`) for supervisor —
ops outside the table are dropped with a NOTICE (mirrors stock "invalid
request"), never answered. **Exemptions:** `kYR_select`/`kYR_try` bypass the
filter — they are streamid-correlated replies to our *own* `kYR_locate`, not
manager-originated requests (try is additionally in both tables anyway). A
supervisor additionally fans manager-forwarded namespace ops DOWN to its
logged-in children (rrdata reparse → `brix_cms_forward_to_node`), matching
supVOps' Forward disposition.

**PR-C — server-leg Admit parity.** The login Mode word is now captured and
the node classified exactly as stock `Admit`: `(manager|subman) ?
(server ? "R" : "M") : "S"`; the role is stamped into the per-worker ctx, the
SHM registry (`role[2]` on `brix_srv_entry_t` + snapshot — dashboard-visible),
and the registration NOTICE (`role=%s`). `kYR_state` fan-out to children now
stamps **`kYR_metaman` (0x08)** when this instance is a pure manager.

**PR-D — `brix_cms_state_relay` (flag, default off).** On a registry miss in
manager mode, the parent's `kYR_state` is parked in a per-worker 64-entry
relay table (TTL 5 s, no SHM/locking — child conns and the upward conn share
the worker) and re-fanned to all logged-in children under a fresh downward
streamid; the first child `kYR_have` is echoed back UP under the parent's
original streamid. Silence on table-full/no-answer = stock "not here". Entries
are flushed on upward disconnect; forged answers cannot consume an entry (see
divergence 3).

### Deliberate divergences (rulings)

1. **Supervisor `prepdel` stays local-exec.** supVOps marks prepdel Forward,
   but `brix_cms_forward_to_node` cannot encode `pdlArgs` (reqid); the
   registry-backed local exec is kept. Revisit only if a real cascaded-stage
   deployment appears.
2. **`kYR_metaman` keys on "no confined local export", not on role.** Stock
   stamps it for `!Config.asServer()`. In brix, a `brix_manager_mode` instance
   leaves `root_canon` empty (`process_server_init.c`) — it can hold nothing
   locally — so the condition is `!caps.supervisor && rootfd < 0`. A
   supervisor-tier relay probe therefore CARRIES metaman (it is a pure routing
   tier), asserted in the round-trip test.
3. **Relay answers bypass the W3 paths-cover gate via an exact-path match.** A
   relayed probe targets a path *outside* every child's declared exports by
   construction (covered paths are answered from the registry without a
   relay), so W3's "have only within your login-Paths" gate would
   unconditionally kill the echo. The relay entry stores the probed path;
   `take()` consumes it only on streamid **and** exact path match (a forged
   path on a real streamid is refused *without* consuming, so the honest
   answer still lands). Trust anchor: a child can only assert paths this
   manager actively probed, once, within the TTL. Stock has no such gate at
   all — this keeps the brix hardening while unblocking recursion.
4. **`kYR_update`/`kYR_status` are dropped under explicit roles** — they are
   absent from stock manVOps/supVOps (stock parity, but a behavior change vs
   `auto`, which accepts them). `auto` remains the default; nothing changes
   for existing configs.

### Out-of-scope register (still open, deliberately)

`XrdCmsManTree`/SanList tree *formation* (nginx supervisors dial a statically
configured parent; no tree negotiation), peer/proxy roles (`kYR_peer`,
`kYR_proxy`), director-leg admit, hop-count limits on recursion (bounded
instead by the single supervisor tier + relay TTL), and `kYR_nostage`/
`kYR_suspend` login-mode side-bits (accepted, not acted on).

### Files

`src/net/cms/`: `send.c` (login Mode), `router.c/.h` (manVOps/supVOps +
role enum), `recv_frame.c` (role filter, supervisor fan-down, relay branch),
`state_relay.c/.h` (NEW), `server.h`/`server_recv_parse.c`/`server_handler.c`
/`server_send.c`/`server_recv_frame.c`/`server_recv_frame_handlers.c` (Admit
classification, metaman, HAVE relay-take), `connect.c` (relay flush),
`cms_internal.h` (constants), `stats_doc`+`send_stats` (PR-A, both legs);
`src/net/manager/registry.c/.h` + `registry_health.c` (role field);
`src/core/types/conf_structs.h` + `server_conf_merge_cluster.c` +
`directives_cms.h` + `module_enums.c` (config); repo `./config`
(state_relay). Tests: `tests/test_cms_wire_pup_conformance.py` + templates
`nginx_cms_wire_role_node.conf`/`nginx_cms_wire_super.conf` + 3 ledger ports
(30412–30414).

> **DESIGN-REFRESH NOTE (2026-07-21 — apply while coding, phase-89 §C.0).**
> Verified still fully open in the tree (no `USAGE`/`STATS`/`PREPADD`/
> `PREPDEL`/`STATE` dispatch cases; incoming `kYR_have` undispatched on the
> manager; none of `loc_cache`/`meter`/`blacklist_file`/`forward_agg` exist).
> Two corrections to this spec's letter:
> 1. **W2 substrate:** `src/frm/` was dissolved by phase-64 P6 —
>    `frm_request_add/_delete` no longer exist. The live API is the
>    stage-engine request registry: `brix_stage_request_add` /
>    `brix_stage_request_delete` / `brix_stage_request_owner_check` on
>    `brix_stage_registry_singleton()`; reference consumer
>    `src/protocols/root/query/prepare.c` (this doc's own pointer, already
>    migrated). ADR-6's D-a sidecar reqid map survives unchanged, retargeted
>    at the registry (it mints its own reqids exactly as FRM did).
> 2. **Naming:** all skeletons are pre-rebrand (`xrootd_*`); the tree is
>    `brix_*`. Each PR re-grounds its Appendix snippets on live symbols.

**Date:** 2026-06-27
**Scope:** `src/net/cms/`, `src/net/manager/`, `src/frm/` (wiring only), config, tests, docs.
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
  `src/protocols/root/query/prepare.c` is the reference consumer): `prepadd`→enqueue stage with
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
  (`src/observability/dashboard/`) — native and authenticated (ADR-2).
- Tests: blacklisted host never selected; file reload picks up edits; dashboard
  drain removes a node from selection.

### W7 — multi-tier clustering (G7)  · ~3–4 wk  **[LANDED 2026-07-27 — see the LANDED block at the top; the phase-62 split was not needed]**
Supervisor / meta-manager / sub-manager cascades (`XrdCmsSupervisor`,
`XrdCmsManTree`, `manVOps` routing). A node runs as **both** a manager (accepting
nodes below) and a heartbeat client (registering up to a meta-manager); locates
recurse up the tree with hop-count limits. We already have both halves (client +
server) in `src/net/cms/` and the sub-manager `state→have` forwarding on the node side
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

/* admin via the dashboard API (src/observability/dashboard/api_admin.c), authenticated:
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
| locate (2) | ✅ static + dynamic (W3) | ✅ (sub-mgr) | dynamic behind `brix_cms_locate_window` (phase-89 PR-5) |
| mkdir (3) | ✅ redirect | ✅ exec | |
| mkpath (4) | ✅ redirect | ✅ exec | |
| mv (5) | ✅ redirect | ✅ exec | |
| prepadd (6) | ✅ W2 (fwd) | ✅ W2 (→ stage-request registry) | reqid-map ADR-6/ADR-2b (FRM API dissolved; phase-89 PR-6) |
| prepdel (7) | ✅ W2 (fwd) | ✅ W2 (→ stage-request registry) | idempotent, silent (phase-89 PR-6) |
| rm (8) | ✅ redirect + W8 fan-out | ✅ exec | fan-out behind `brix_cms_fanout` (phase-89 PR-8) |
| rmdir (9) | ✅ redirect + W8 fan-out | ✅ exec | " |
| select (10) | ✅ | ✅ | W5 ✅ — affinity + multi via root-plane locate (`brix_cms_affinity`/`_locate_multi`, phase-89 PR-7) |
| stats (11) | ✅ W1 size + full XML | — | byte-exact Cluster.Stats role doc (W7 PR-A, 2026-07-27) |
| avail (12) | ✅ | — | |
| disc (13) | ✅ | ✅ | |
| gone (14) | ✅ | — | path deregister |
| have (15) | ✅ W3 (cache) | ✅ emit | first-have-wins wake + loc cache (phase-89 PR-5) |
| load (16) | ✅ recv + W4 vector | — | `/proc` meter fills theLoad (phase-89 PR-3) |
| ping (17) | ✅ | ✅ | |
| pong (18) | ✅ | — | |
| space (19) | ✅ | ✅ | |
| state (20) | ✅ W3 emit | ✅ answer | manager probe fan-out (phase-89 PR-5) |
| statfs (21) | ✅ | — | |
| status (22) | ✅ incl. W9 reset | ✅ incl. W9 | reset/suspend/resume/stage + vnid (phase-89 PR-2) |
| trunc (23) | ✅ redirect | ✅ exec | |
| try (24) | ✅ recv | ✅ recv | W5 reason constants landed as decode vocabulary; list EMIT n/a in this topology (phase-89 PR-7 deviation) |
| update (25) | ✅ | ✅ | |
| usage (26) | ✅ W1 (→load) | — | 13-byte golden (phase-89 PR-1) |
| xauth (27) | ✅ | — | sss |
| (meta routing manVOps) | ✅ W7 | ✅ W7 | `brix_cms_role` valid-ops tables + supervisor fan-down + `brix_cms_state_relay` (LANDED block, 2026-07-27) |

Net (matrix fully flipped 2026-07-27 — phase-89 §C per-PR records + the W7
LANDED block above): **every row is wired on the role(s) that use it**; the
remaining deltas vs stock are the deliberate divergences and the out-of-scope
register in the LANDED block.

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
