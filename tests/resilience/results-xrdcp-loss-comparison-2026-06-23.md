# xrdcp under packet loss — repo client+module vs official client+xrootd

**Date:** 2026-06-23
**Harness:** `tests/resilience/run_xrdcp_loss.py` → `tests/c/fault_proxy.c` (`lossy`
lever, ppm resolution) in front of anonymous `root://` servers.
**Transfer:** download a 64 MiB file with `xrdcp`, 8 reps/cell, byte-exact (md5)
verified, per-copy wall-clock bound 120 s.

A point-in-time comparison of how the **repo's native client + nginx module** hold
up under wire loss versus the **stock XRootD client + xrootd daemon**, on the same
loss grid, same file, same fault proxy. WSL2 loopback — absolute MB/s are not
representative of real hardware; the *shape* of each client's loss response and the
integrity/failure semantics are the durable findings.

## What "loss %" means here

`lossy <pct>` severs the whole TCP connection with `<pct>%` probability **per 64 KB
forwarded chunk** — an application-visible reset, harsher than `netem`-style packet
loss (where TCP retransmits transparently). Both *data* and *request* PDUs traverse
the proxy, so a client that issues many small requests is exposed to more sever
opportunities than one that batches into few large requests. See the NOTE in
`tests/c/fault_proxy.c`.

## Reproduce

```bash
PYTHONPATH=tests python3 tests/resilience/run_xrdcp_loss.py \
    --levels 0,0.0001,0.001,0.01,0.1,1.0 --size-mib 64 --reps 8 --matrix
```

`--matrix` runs all four client×server pairs (the diagonal + cross pairs), which
separates client-driven from server-driven effects.

---

## Headline: the two requested pairs (median MB/s of successful copies)

| loss % | repo→nginx | official→xrootd |
|---:|---:|---:|
| 0       | 1100 | 1198 |
| 0.0001  | 1100 | 1177 |
| 0.001   | 1137 | 1243 |
| 0.01    |  729 | 1032 |
| 0.1     |  231 | 1002 |
| 1.0     |  107 |  **2.2** |

All cells **8/8 byte-exact** except as noted below.

## Full matrix (median MB/s; ok/N if not 8/8)

| loss % | repo→nginx | repo→xrootd | official→nginx | official→xrootd |
|---:|---:|---:|---:|---:|
| 0       | 1100 | 1017 | 1119 | 1198 |
| 0.0001  | 1100 | 1017 | 1119 | 1177 |
| 0.001   | 1137 | 1032 | 1002 | 1243 |
| 0.01    |  729 |  729 |  883 | 1032 |
| 0.1     |  231 |  236 |  895 | 1002 |
| 1.0     |  107 |  104 |  473 (7/8) | 2.2 |

---

## Findings

1. **Sub-0.001% loss is free for everyone.** From 0 to 0.001%, all four pairs run at
   ~1000–1240 MB/s, byte-exact. (Statistically <0.01 severs per 64 MiB transfer.)

2. **The two clients have opposite loss-response shapes:**
   - **repo `xrdcp` — smooth, bounded, server-independent.** It starts slowing at
     0.01% and declines monotonically (0.1% → ~231, 1% → ~107 MB/s), but it
     **completes every single copy (8/8) at every level**, with bounded latency
     (≤0.65 s for 64 MiB at 1%), and the curve is **identical on nginx and xrootd**
     (1% : 107 vs 104). Its degradation is entirely client-driven.
   - **official `xrdcp` — flat then a fragile cliff.** It holds near line rate much
     longer (1002 MB/s at 0.1% vs repo's 231), but at 1% it becomes **server-
     dependent and brittle**:
     - → xrootd: collapses to **2.2 MB/s**, individual copies stalling 15–45 s each
       (XrdCl's default per-failure recovery/timeout window — the 15/30/45 s steps).
       It still completes, just very slowly.
     - → nginx: **473 MB/s but 7/8** — one outright failure (`rc=51 [ERROR] Invalid
       session`).

3. **Cross-matrix isolates cause:** the *degradation curve* is client-driven (repo
   degrades the same on both servers; official stays flat on both up to 0.1%), while
   the *1% failure mode* is an interaction (official→xrootd stalls, official→nginx
   errors). The repo client's smaller/more-frequent requests expose it to severs
   earlier; its recovery is cheap (immediate reconnect+resume), so it trades raw
   throughput for **predictable, bounded, 100%-reliable** behaviour. The official
   client batches more (less exposure → flat longer) but its default recovery is
   heavyweight (long stalls) and occasionally fails outright under heavy churn.

4. **Integrity is absolute.** Across 384 copies, every success was byte-exact md5.
   The single non-success (official→nginx @ 1%) was a *clean error*, never silent
   corruption.

## Caveats

- **Out-of-the-box defaults.** The repo client used `XRDC_MAX_STALL_MS=30000` (its
  default) and retries cheaply; the official client ran on stock XrdCl `XRD_*`
  defaults, whose request/stream timeouts dominate its 1% behaviour. Tuning
  `XRD_STREAMTIMEOUT`/`XRD_REQUESTTIMEOUT`/`XRD_CONNECTIONWINDOW` would change the
  official client's 1% numbers — this compares default behaviour, not tuned ceilings.
- **Reset-flavour loss**, not `netem` packet drop (see above). It stresses
  reconnect/resume, which is the point.
- **WSL2 loopback**: >1 GB/s baselines are memory-bandwidth artefacts; treat as
  relative, not absolute.

## Follow-up: tuning the repo client's recovery window for maximal performance

The repo client's degradation was traced to its **transport-fault backoff**: after
each sever it sleeps `25 ms << attempt` (capped 250 ms) before reconnecting
(`brix_backoff_delay_fast_ms` in `client/lib/nettmo.c`). On a lossy-but-*connected*
link the reconnect itself is sub-millisecond, so that sleep — not the reconnect — is
the dominant per-sever cost (~10 severs × ~25–40 ms ≈ the ~0.5 s seen at 1%).

The backoff base was made tunable via **`XRDC_BACKOFF_BASE_MS`** (default 25, so stock
behaviour is unchanged) and the comparison re-run with the repo client at base = 1 ms
(`repo-fast`). 64 MiB, 8 reps, same servers/grid.

### Head-to-head (median MB/s of successful copies)

| loss % | repo→nginx (stock, 25 ms) | repo-fast→nginx (1 ms) | official→xrootd |
|---:|---:|---:|---:|
| 0      | 1032 |  919 | 678 |
| 0.0001 |  907 | 1002 | 1002 |
| 0.001  |  932 |  973 | 1177 |
| 0.01   |  645 |  959 |  895 |
| 0.1    |  233 |  860 |  282 (6/8) |
| 1.0    |  104 |  658 |  2.2 |

(Cross-matrix confirms it's server-independent: `repo-fast→xrootd` tracks
`repo-fast→nginx` — 0.1% : 932, 1% : 763 — and stock `repo→xrootd` tracks
`repo→nginx` — 0.1% : 230, 1% : 104. The backoff, not the server, was the bottleneck.)

### Effect of the tuning (repo, nginx)

| loss % | stock MB/s | tuned MB/s | speed-up |
|---:|---:|---:|---:|
| 0.01 | 645 | 959 | 1.5× |
| 0.1  | 233 | 860 | **3.7×** |
| 1.0  | 104 | 658 | **6.3×** |

### Findings (tuned)

1. **The repo client becomes nearly loss-insensitive up to 0.1%** (860–960 MB/s ≈
   baseline) and pays only ~35% at 1% (658 MB/s), **still 8/8 byte-exact** at every
   level. The knob is the single biggest lever: 6.3× at 1%.
2. **Tuned repo now dominates the official client under loss** — at 0.1% it's ~3×
   faster *and* 8/8 vs official's 6/8 (two `Invalid session` failures); at 1% it's
   ~300× faster than official→xrootd (658 vs 2.2 MB/s) while official stalls ~30 s
   per copy on XrdCl's default recovery timers.
3. **No cost when clean.** repo-fast at 0–0.001% is within run-to-run noise of stock
   (~900–1000 MB/s); minimising the backoff doesn't hurt the loss-free path.
4. **Trade-off (honest):** base = 1 ms makes retries more aggressive against a
   genuinely *down* server. This is bounded — the design already fast-fails on
   `ECONNREFUSED` for never-established connections (only a link that *was* up and got
   severed uses this path), the escalating shift still backs off (cap 10 ms at base 1),
   and the `XRDC_MAX_STALL_MS` patience window still bounds total effort. For a merely
   *overloaded* (not lossy) server a slightly larger base (e.g. 5–10) is gentler; 1 ms
   is the max-throughput-under-loss setting.

## Bottom line

For realistic low loss (≤0.001%) the repo client+module and the stock client+xrootd
are indistinguishable — both line-rate and byte-exact. As loss climbs the two trade
places on *what* they optimise: the stock repo client degrades gracefully and
reliably but slowly; the official client stays fast for longer then hits a sharp,
server-dependent cliff at 1% (30 s stalls on xrootd, or `Invalid session` errors).

**With one tuning knob (`XRDC_BACKOFF_BASE_MS=1`) the repo client wins outright:**
near-baseline throughput up to 0.1% (860 MB/s) and 658 MB/s at 1% — 6.3× the stock
repo client and ~300× the official client at 1% — while staying 8/8 byte-exact and
server-independent. Neither client ever corrupted data; the repo client's advantage
is that its recovery latency is a *tunable* (and now a one-env-var win), whereas the
official client's is buried in XrdCl's default timers.

---

# Out-of-order (reorder) comparison

Same clients, servers, levels (0/0.0001/0.001/0.01/0.1/1.0 %) and 8 reps, but with
the proxy's **`reorder`** lever instead of `lossy`: with `<pct>%` probability per
64 KB chunk, hold that chunk back by 50 ms while later chunks pass — the app-layer
analog of `tc netem reorder` (out-of-order delivery, which on TCP is reassembled in
order and surfaces only as added latency; it never severs). The `reorder` lever was
upgraded to ppm resolution for the fractional levels.

```bash
PYTHONPATH=tests python3 tests/resilience/run_xrdcp_loss.py \
    --fault reorder --reorder-ms 50 --levels 0,0.0001,0.001,0.01,0.1,1.0 \
    --size-mib 64 --reps 8 --matrix
```

## Head-to-head (median MB/s of successful copies)

| reorder % | repo→nginx (25 ms) | repo-fast→nginx (1 ms) | official→xrootd |
|---:|---:|---:|---:|
| 0      |  907 | 1082 | 1119 |
| 0.0001 |  799 | 1017 | 1119 |
| 0.001  |  959 | 1119 | 1157 |
| 0.01   |  559 |  569 |  639 |
| 0.1    |  306 |  305 |  323 |
| 1.0    |  118 |  119 |  121 |

Full matrix (all six pairs) converges to the same curve, e.g. at 1%: repo→nginx 118,
repo→xrootd 119, repo-fast→nginx 119, repo-fast→xrootd 117, official→nginx 120,
official→xrootd 121. **All 288 copies 8/8 byte-exact; zero failures, zero stalls.**

## Findings (reorder) — the opposite of the loss case

1. **Reordering is a uniform latency tax, not a resilience challenge.** Every
   client×server pair degrades along the *same* curve (1% : ~120 MB/s for all six),
   because a held-back chunk just delays the in-order TCP byte stream — there is no
   sever, so no reconnect, so no recovery logic to differentiate the clients.
2. **The loss-tuning knob does nothing here.** `repo-fast` (backoff = 1 ms) is
   identical to stock `repo` under reorder (1% : 119 vs 118) — exactly as expected,
   since `XRDC_BACKOFF_BASE_MS` only affects the reconnect path, which reordering
   never triggers. (Contrast the loss sweep, where it was a 6.3× win.)
3. **No client advantage either way.** Unlike loss — where the official client
   collapsed to 2.2 MB/s at 1% on xrootd — under reorder the official client is
   neither better nor worse than the repo client; all converge (~120 MB/s at 1%).
4. **The degradation scales with the hold budget**, not the client: ≈ (chunks ×
   rate × 50 ms). It is flat to baseline through ~0.001%, then ~640 (0.01%),
   ~320 (0.1%), ~120 MB/s (1%) for everyone. A smaller `--reorder-ms` shifts the
   whole curve up uniformly.
5. **Integrity absolute:** 288/288 byte-exact.

## Loss vs reorder — the contrast in one line

Packet **loss** (severs) is a *recovery* problem → clients diverge enormously and
tuning matters (repo-fast 658 vs official 2.2 MB/s at 1%). Packet **reorder**
(latency) is a *physics* problem → all clients pay the same tax and tuning is
irrelevant (~120 MB/s at 1% for every client+server). Both preserve byte-exact data.
