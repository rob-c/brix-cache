# Phase 99 — DPI / Middlebox Pathology Levers for `brix-fault-proxy`

**Status:** LANDED (2026-08-05) — Waves A (all 10 levers), B (frag-drop /
first-not-syn-drop / strip-opt-degrade) and C (UDP relay + 4 levers) implemented,
built clean under `-Wall -Wextra`, and tested green
(`tests/test_fault_proxy_dpi.py` 11, `tests/test_fault_proxy_udp.py` 3, Wave-B
cases in `tests/test_fault_proxy_privileged.py` 3); no regressions in the existing
fault-proxy suites (the 29 `test_fault_proxy_fidelity.py` failures are pre-existing
on this branch — verified identical against a pristine `HEAD` build — and are
unrelated to this phase). · **Owner:** client-tooling
**Depends on:** the fault-proxy core as it stands on `feat/deleg-matrix-token-x509`
(the `http header-hold` DPI lever already landed here — see
`tests/test_fault_proxy_header_hold.py`). Several earlier phases remain unmerged;
this plan is **purely additive** to the fault-proxy TUs and takes no dependency on
them, so it can land independently and rebase cleanly.
**Scope:** `client/apps/diag/brix_fault_*.{c,h}`, `client/man/brix-fault-proxy.1`,
`client/Makefile` (`FAULT_PROXY_SRCS`), the Python suite under `tests/`, and
`docs/09-developer-guide/fault-proxy-privileged-levers.md`.

---

## 0. Motivation

An overloaded or grossly mis-configured cloud DPI/firewall introduces a family of
failures that are invisible to a browser but lethal to grid/HEP/storage tooling
(XRootD, GridFTP/FTS, HTTP-TPC, WebDAV, RUCIO, cmsd, GSI mutual-TLS). The
`header-hold` lever reproduced the first of these (stalling on header size). This
phase reproduces the rest, faithfully, in the same root-free-first, control-verb +
`--flag`, 3-test-per-change idiom.

The catalogue and its HEP-specific bite are recorded below inline with each lever.
The organising principle is unchanged from the feature-expansion plan: **compose
new behaviours from the existing primitives**, keep every TU under the 600-line
guard, gate anything below TCP behind `--privileged`, and add exactly one new
*data path* (UDP) as its own scoped tranche.

---

## 1. Design principles (inherited)

- **Root-free by default.** Waves A land as pure userland relay logic; only Wave B
  touches the kernel and stays behind the existing `--privileged` gate; Wave C
  adds a UDP relay path that is itself root-free.
- **One source of truth per lever.** Config lives in a per-direction struct;
  mutation goes through `apply_command`; `--flag` reprojects to the same verb
  (`fp_apply_lever_opt` table in `brix_fault_cli.c`). `clear`/`http off`/
  `reset_lever` must zero every new field so tests never leak.
- **Timing effects live in the pump, rewrites in the rewriter.** As with
  `header-hold`, a stall/kill/throttle is applied in `brix_fault_pump.c` and is
  **excluded from `fp_*_active()`** predicates that gate the buffer-rewrite path.
- **Counters + status for every lever.** Each adds one `fp_counters` field, a text
  `status` token, and a `status json` key (test oracle).
- **3-test ritual:** success + error/no-trigger + security/negative, self-contained
  against a throwaway echo server on ephemeral loopback ports (no root, no fleet).
- **File-size governance:** new verbs attach to the smallest fitting existing TU;
  a new TU is created only when an existing one would cross ~560 lines. New TUs go
  in `FAULT_PROXY_SRCS` (one Makefile line each; the tool is standalone, not in
  `./config`/RPM). Current headroom: `cmd_attack.c` 518, `report.c` 498,
  `relay.c` 457, `pump.c` 448 — Wave A needs one new TU (`brix_fault_cmd_dpi.c`).

---

## 2. Wave A — root-free DPI lever tranche

New verb dispatch collected in **`brix_fault_cmd_dpi.c`** (new TU), wired into the
`apply_command` chain next to `cmd_set_attack`. Shared per-direction state added to
`brix_fault_proxy_state.h`. All levers accept the trailing `up|down|both` token via
`dir_of()`.

### A1 — `idle-reap <ms> [black-hole|rst]`  *(the #1 real-world killer)*
A DPI evicts an idle flow from its conntrack table, then **black-holes** subsequent
packets (no RST/FIN). Long-lived XRootD/GridFTP **control channels** that go quiet
during a bulk data transfer, or an idle redirector/DB socket, hang until the kernel
TCP timeout (minutes). Invisible to Chrome; fatal to a 4-hour transfer.

- **State:** `volatile int g_idle_reap_ms; volatile int g_idle_reap_mode;` (0=black
  -hole, 1=rst), per direction.
- **Wire:** `brix_fault_pump.c` `relay_pump` — track per-direction
  `last_activity_ms` (monotonic, updated on any byte in that direction). When
  `now - last > g_idle_reap_ms`: black-hole ⇒ stop arming `POLLIN` for that
  direction and silently discard further reads (connection stalls, no teardown);
  rst ⇒ `sever(cfd, ufd, /*abortive=*/1)` + `CDEC`. Reuses `pump_arm_events` and
  `sever`.
- **Counter:** `reaped`. **Status:** `idle-reap=<ms>/<mode>`.
- **Tests:** quiet channel past the deadline stalls (black-hole) / gets a RST;
  a channel kept warm below the deadline is untouched; `clear` disarms.

### A2 — `body-hold <thresh> <ms> [partial|whole]`  *(store-and-forward class)*
Generalises `header-hold` to the **body**: a store-and-forward middlebox buffers
the whole message before releasing it, killing streaming/chunked/long-poll and
adding latency ∝ body size. Reuses the header-hold machinery almost verbatim.

- **State:** extend `fp_http_cfg` with `body_hold_thresh/ms/partial` (excluded from
  `fp_http_active`, sibling of the hold fields).
- **Wire:** `fp_http_hold_decide` gains a body variant `fp_http_body_hold_decide`
  that measures **bytes after** the `CRLFCRLF` (or the whole segment when no header
  is present, i.e. a pure body continuation); same release/stall logic in
  `relay_pump_dir`.
- **Counter:** reuse `held` (or add `body_held`). **Status:** `body-hold` token.
- **Tests:** oversized body stalled whole / partial-split; small body passes;
  header-only segment not double-counted.

### A3 — `eat-100-continue`
Box swallows the `100 Continue` interim response → `Expect: 100-continue`
PUT/uploads hang forever waiting for a 100 it ate.

- **State:** `volatile int g_eat_100;` (down direction only — it's a response).
- **Wire:** `brix_fault_pump.c` — on the down path, scan the segment for a
  `HTTP/1.1 100`…`\r\n\r\n` interim status line and splice it out (drop those
  bytes, forward the remainder). Pure byte edit; reuse the `pump_chain` scratch
  flip. Idempotent, only the interim response is removed.
- **Counter:** `ate_100`. **Status:** `eat-100=<0|1>`.
- **Tests:** a spliced 100-continue is removed and the final response still
  arrives; a non-100 response is untouched; disarm restores.

### A4 — `rst-after <bytes|ms> <n>` and `max-bytes <n>`
Delayed classify-and-kill: the flow "works for 2 s / 8 MB, then dies" as the box
finishes classifying it, or a hard byte-guillotine. `max-lifetime` already covers
the time axis at connection scope; these add **per-direction byte** and a
forged-RST-after-classify semantics.

- **State:** `volatile long g_rst_after_bytes; volatile long g_rst_after_ms;`
  (either arms the kill; whichever trips first). `max-bytes` ⇒ `g_rst_after_bytes`
  with abortive off (clean FIN) vs on (forged RST).
- **Wire:** `brix_fault_pump.c` `pump_severed` — extend the guillotine check to
  the running per-direction byte total (already tracked via `up_ctr/down_ctr`) and
  the byte/ms thresholds.
- **Counter:** reuse `severs` + a `classify_kills` tally. **Status:**
  `rst-after=<bytes>B/<ms>ms`.
- **Tests:** transfer dies exactly past the byte/ms threshold with the configured
  teardown; under-threshold transfers complete; disarm.

### A5 — `drop-fin [up|down]`
Asymmetric teardown: box passes data but drops the FIN → peers stuck in
`FIN_WAIT`/`CLOSE_WAIT`, fd/handle leaks in pooled clients (XRootD handle pool,
libcurl multi).

- **State:** `volatile int g_drop_fin_up/down;`
- **Wire:** `brix_fault_pump.c` — on read EOF (`nr==0`) for the armed direction,
  do **not** propagate the shutdown to the peer; keep the other half open (reuse
  the half-close plumbing: `shutdown(SHUT_RD)` locally, never `SHUT_WR` the peer).
- **Counter:** `fin_dropped`. **Status:** `drop-fin=<up>/<down>`.
- **Tests:** peer never observes EOF within the window; the reverse direction keeps
  flowing; disarm propagates FIN normally.

### A6 — `classify-throttle <bytes> <kbps>`
Volume-heuristic slow-lane: full rate until N bytes (box decides the flow "looks
like exfiltration"), then clamp to `<kbps>`. Misclassified XRootD/GridFTP shunted
to a slow lane mid-transfer.

- **State:** `volatile long g_classify_bytes; volatile int g_classify_kbps;` per
  direction.
- **Wire:** `brix_fault_relay.c` `forward_faulted` — once the direction's running
  byte total exceeds `g_classify_bytes`, fold a `rate_kbps` clamp onto the lever
  snapshot (reuse the existing token-bucket rate path). Zero cost below the
  threshold.
- **Counter:** `throttled` (segments in the slow lane). **Status:**
  `classify-throttle=<bytes>B/<kbps>`.
- **Tests:** first N bytes run at line rate, subsequent bytes are paced;
  under-N transfers unaffected; disarm.

### A7 — `alg-rewrite <ip:port> <ip:port> [up|down]`  *(the FTP/GridFTP ALG)*
An application-layer gateway that "helps" by rewriting an `IP:port` embedded in the
byte stream (FTP `PORT`/`227 PASV`, or any protocol carrying an endpoint in
payload) → data-channel points at the wrong endpoint, and the length-changing
rewrite corrupts framing/checksums. Faithful reproduction of "middlebox edits bytes
inside a stream it doesn't understand."

- **Implementation:** a thin front-end over the existing `replace` primitive in
  `brix_fault_ext.c` — parse the two `IP:port` strings into search/replace byte
  patterns (dotted-quad + port as ASCII, and optionally the FTP `h1,h2,h3,h4,p1,p2`
  comma form) and install them as a `replace` pair. No new mutate engine.
- **Counter:** reuse `replaced`. **Status:** covered by the ext `replace` line.
- **Tests:** an FTP `227 Entering Passive Mode (a,b,c,d,p1,p2)` line is rewritten
  to the spoofed endpoint; a stream without the pattern is untouched; the
  length-delta framing corruption is observable.

### A8 — `hello-split-reset <thresh>`  *(TLS/PQC ClientHello intolerance)*
Box only inspects the first TCP segment; a **ClientHello that spans segments**
(post-quantum hybrid keyshare X25519MLKEM768 blows past one MSS, or a large SNI/
cert list) is misparsed → RST. Direct cousin of `header-hold`, on the handshake.

- **Implementation:** reuse `header-hold`'s "complete block ≥ threshold" decision,
  but keyed on a **TLS record** (content-type `0x16` handshake, `ClientHello`
  `0x01`) whose declared length exceeds `<thresh>` → `sever(abortive)` instead of
  stalling. Lives beside the TLS surgery in `brix_fault_tls.c` /
  `apply_tls` gate in `relay.c`.
- **Counter:** `hello_reset`. **Status:** `hello-split-reset=<thresh>`.
- **Tests:** an oversized ClientHello triggers a RST; a small one passes; non-TLS
  traffic is ignored.

### A9 — `syn-drop <ppm>`
New-connection rate-limiting under load → intermittent connect timeouts, worst on
fan-out (parallel data streams, native TPC, `xrdcp --parallel`). Complements the
existing `accept-pause`/`refuse`.

- **State:** `volatile int g_syn_drop_ppm;`
- **Wire:** `brix_fault_proxy.c` `fp_accept_loop` — a seeded roll that `close()`s
  the accepted client *silently* (no RST-to-refuse) so the SYN "never happened"
  from the client's view. Distinct from `refuse` (which is a clean refusal).
- **Counter:** reuse `refused` + a `syn_dropped` tally. **Status:** `syn-drop=<ppm>`.
- **Tests:** at 1e6 ppm every connect times out (no RST); at 0 all succeed; the
  established-connection path is unaffected.

### A10 — header/`Range` surgery (compose, no new engine)
`Range`-strip → XRootD **vector/partial reads** silently become full-object
downloads (massive over-read); `Connection: close` inject → keep-alive defeated →
connection churn + conntrack pressure. Both are expressible as **`http`**
sub-verbs; add `http strip-header <name>` (the inverse of the existing
`inject-header`) and document the `Range`/`Connection` recipes. Lives in
`brix_fault_cmd_attack.c` `http_apply` + a strip branch in `fp_http_rewrite`
(drop any header line whose name matches, during `http_emit_headers`).
- **Counter:** reuse `http_rewrites`. **Tests:** `Range` removed → upstream sees no
  Range; `Connection: close` injected; unrelated headers preserved.

---

## 3. Wave B — privileged (below-TCP) extensions

Behind the existing `--privileged` gate; extend `brix_fault_priv*.c` (nft/netem
plane). Same teardown/atexit discipline (`fp_priv_teardown`).

### B1 — `priv strip-opt <sack|wscale|timestamps|tfo|all>`  *(LFN throughput killer)*
A transparent proxy that strips TCP options: dropping **Window Scale** caps the
window at 64 KB → transatlantic HEP throughput floored to `64KB/RTT`; dropping
**SACK** makes any loss catastrophic. Small transfers unaffected → invisible.
- **Implementation:** `nft`/`tc` cannot rewrite TCP options portably; use an
  `iptables`/`nftables` `NFQUEUE` verdict handler *or* an `eBPF`/`tc` clsact filter
  that clears the option in the SYN. Scoped to the listen/target ports. Documented
  as the one lever that may require an extra kernel feature; degrade with a clear
  `err:` when unavailable. Partial userland approximation already exists via
  `rcvbuf`/`sndbuf` clamps.
- **Counter:** `opt_stripped`. **Tests:** netns root test (per the fault-proxy
  privileged test pattern) asserting the peer's SYN lost the option.

### B2 — `priv frag-drop`  *(fragmented UDP / large DNS)*
Drop all IP fragments → fragmented large UDP (big EDNS0/DNS, some GSI callbacks)
fails while small requests succeed. One `nft` rule (`ip frag-off & 0x1fff != 0
drop`) added to the existing `brix_fault_proxy` table.
- **Tests:** netns — a fragmented datagram is dropped, an unfragmented one passes.

### B3 — `priv first-not-syn-drop`
Box loses state (failover/ECMP rehash/asymmetric routing) and drops any non-SYN
packet that doesn't match a (now-absent) state entry → mid-stream freeze. `nft`
`ct state invalid`/`tcp flags != syn` drop scoped to ports, armed on demand.
- **Tests:** netns — an established flow is frozen after arming; a fresh handshake
  recovers.

(The **PMTUD black hole** and **ICMP-admin** members of this family are already
covered by the existing `priv mtu` and `priv cut icmp-*` levers — cross-reference,
do not duplicate.)

---

## 4. Wave C — UDP data path (new surface)

The one genuinely new *data path*. Today the proxy is TCP-only, so the entire
UDP-vs-TCP pathology class (the user's canonical "UDP sent ahead of the TCP traffic
doesn't work") is unreachable from userland. Add a minimal UDP relay in a new TU
**`brix_fault_udp.c`**, opt-in via `--udp <listen> <target>` (a UDP listener that
forwards datagrams both ways with a per-src flow map), so the DPI-vs-UDP levers can
act on real datagrams.

Levers (root-free, on the UDP relay):
- **`udp-drop <ppm>`** — deprioritised/dropped UDP while TCP flows (QUIC/H3, mtr,
  GridFTP-UDT, multicast cmsd/monitoring, NTP, Kerberos-over-UDP).
- **`udp-hold-until-tcp <ms>`** — buffer the **first** datagram of a flow and
  release it only after `<ms>` (mimics "UDP allowed only as *related* to an
  established TCP flow"): protocols that fire a UDP probe *ahead of* TCP break.
  This is the user's literal example.
- **`udp-reap <ms>`** — UDP flow-map timeout far shorter than TCP → long-lived UDP
  monitoring/streams reaped early.
- **`udp-reorder <ppm> <ms>`** — reorder datagrams (and, combined with a TCP route
  on the same daemon, reorder UDP *relative to* TCP).

- **Counters:** `udp_in/out/dropped/reaped/held`. **Status:** a new `udp …` line.
- **Tests:** a fresh `tests/test_fault_proxy_udp.py` with a UDP echo server —
  drop-rate, first-datagram hold latency, flow-map reap, reorder; plus a
  combined-route test that a UDP probe fired before its TCP flow is delayed while
  TCP is unaffected.

Privileged UDP variants (delay/loss/reorder on the wire, independent of the relay)
are already expressible via `priv netem` on `--priv-iface`; cross-reference.

---

## 5. Feature → mechanism matrix

| # | Lever | Class | Mechanism | New TU? |
|---|-------|-------|-----------|---------|
| A1 | `idle-reap` | state reaping | pump activity timer + sever/black-hole | cmd_dpi |
| A2 | `body-hold` | store-and-forward | `fp_http_body_hold_decide` (header-hold sibling) | no |
| A3 | `eat-100-continue` | HTTP interim | down-path splice | no |
| A4 | `rst-after`/`max-bytes` | classify-kill | `pump_severed` byte/ms guillotine | no |
| A5 | `drop-fin` | asymmetric teardown | EOF non-propagation | no |
| A6 | `classify-throttle` | volume slow-lane | rate clamp after N bytes | no |
| A7 | `alg-rewrite` | payload ALG | front-end over `replace` | no |
| A8 | `hello-split-reset` | TLS/PQC intolerance | TLS-record threshold → RST | no |
| A9 | `syn-drop` | conn rate-limit | silent accept drop | no |
| A10 | `http strip-header` | header surgery | rewriter drop-line | no |
| B1 | `priv strip-opt` | TCP-option strip | NFQUEUE/eBPF | priv |
| B2 | `priv frag-drop` | fragment drop | nft rule | priv |
| B3 | `priv first-not-syn-drop` | state loss | nft ct-invalid | priv |
| C1 | `udp-drop`/`-hold-until-tcp`/`-reap`/`-reorder` | UDP vs TCP | new UDP relay | brix_fault_udp |

Already shipped (cross-reference, do **not** re-implement): `header-hold`,
`mtu` (PMTUD black hole), `cut icmp-*`, `mss`, `rcvbuf`/`sndbuf`, `accept-pause`,
`fanout`, `max-lifetime`, abortive `one-shot` RST, `replace`/`inject`,
`http inject-header`, netem `delay|loss|reorder|rate|limit`.

---

## 6. Build / governance / invariants

- **Makefile:** `brix_fault_cmd_dpi.c` and `brix_fault_udp.c` are the only two new
  TUs; each adds one line to `FAULT_PROXY_SRCS` (`client/Makefile`). The tool is
  standalone (not in `./config`/RPM), so `check_client_build_coverage.py` is
  satisfied by the Makefile edit alone.
- **File-size guard (<600):** every new/edited TU must stay under the guard. Wave A
  logic is split between `cmd_dpi.c` (dispatch/parse) and the existing pump/relay
  hot paths (a few lines each); `report.c` (498) gains ~8 status tokens + json keys
  — watch the ceiling, spill the json snapshot into `brix_fault_proxy_json.c`
  (277) if needed.
- **Invariants:** no new globals beyond the per-direction lever fields (all reset by
  `clear`/`reset_lever`); no `goto`; functional/early-return; every timing effect
  stays out of `fp_*_active()`; privileged levers keep the atexit/SIG teardown.
- **VFS seam / auth invariants:** N/A — the fault proxy is a standalone client tool
  with no `src/` or storage-backend surface.

## 7. Test plan (3-per-lever ritual)

- **Wave A:** extend `tests/test_fault_proxy_dpi.py` (new) — one class per lever,
  success + no-trigger + security/negative, against the `_CapEcho`/`_ttfb` harness
  already proven in `test_fault_proxy_header_hold.py`. Assert on the `status json`
  counter oracle, on timing (TTFB), and on the bytes the peer observes.
- **Wave B:** extend `tests/test_fault_proxy_privileged.py` — netns root tests
  (skipped without root/`CAP_NET_ADMIN`), asserting the below-TCP effect and clean
  teardown on exit.
- **Wave C:** new `tests/test_fault_proxy_udp.py` — UDP echo server; drop-rate,
  first-datagram hold, flow reap, reorder, and a combined TCP+UDP route proving the
  "UDP ahead of TCP" stall.
- **Regression gate:** the existing `test_fault_proxy_{attack,mitm,protocol,
  fidelity,header_hold}.py` must stay green (status text/JSON shape changes are
  additive — append new keys, never reorder existing ones consumed by tests).

## 8. Suggested landing order

1. **Wave A tranche** (A1–A10) as one reviewable series — highest infuriation-per-
   LOC, all root-free, all composed from shipped primitives. A1 (`idle-reap`) and
   A2 (`body-hold`) first: they cover the two most common real-world outages.
2. **Wave C** (UDP path) as a separate scoped series — it adds a data path, so it
   warrants its own review and its own test file.
3. **Wave B** (privileged) last — smallest audience, needs root/netns CI and, for
   B1, an optional kernel feature; land behind the existing `--privileged` gate.

Docs (`man` + `fault-proxy-privileged-levers.md`) updated per wave, exactly as the
`header-hold` change did.
