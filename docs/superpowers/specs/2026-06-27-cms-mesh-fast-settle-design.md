# CMS mesh fast settle (quick, correct same-host cluster formation)

**Date:** 2026-06-27
**Status:** approved (design) — ready for implementation plan
**Driver:** multi-server CMS meshes (and more complex topologies) should settle
**very quickly** and **correctly connect** to each other, **especially on the same
host**. Speed and correctness weighted equally; measure-first.

## Goal

When a CMS cluster (data nodes, sub-managers, a meta-manager) is brought up — most
acutely when several roles boot near-simultaneously on one host — every node should
register with its manager and the whole mesh should become resolvable (locates
redirect correctly) in **tens of milliseconds**, not the multiple seconds it takes
today. No regression to cmsd wire parity, dead-peer detection, or thundering-herd
protection.

## Root cause (today's behaviour)

The CMS **client** state machine (`src/net/cms/connect.c`) settles slowly when the mesh
boots together:

1. **Fixed 1s initial delay** — every worker waits
   `NGX_XROOTD_CMS_INITIAL_DELAY` (1000 ms) before its first connect attempt
   (`ngx_xrootd_cms_start` → `ngx_xrootd_cms_schedule`).
2. **Exponential backoff on a *refused* connect** — when a node's first attempt
   (at t≈1s) reaches a manager whose listen socket is not up yet, the connect is
   refused and `ngx_xrootd_cms_schedule_retry` jumps straight to
   `min(cms_interval×1000, 6000)` ms of backoff (doubling thereafter). The code does
   **not** distinguish "manager still booting — retry in milliseconds" from "manager
   black-holed — back off".

Net: a node whose manager is ~1s late to listen takes **1s + 2–6s** to register the
first time, and **multi-tier meshes compound this per tier** (leaf→sub-manager→meta).
On the same host, where everything starts together and listen sockets race, this is
the dominant settle cost and the reason a mesh can momentarily look like it "didn't
connect".

The manager-accept side (`src/net/cms/server_handler.c`) already registers a node on
login with no added delay, so no change is needed there.

## Design

Measure-first, then a targeted fix. General adaptive behaviour with a tuned loopback
profile; excellent automatic defaults plus two operator tunables.

### Stage 1 — Measure

- **Per-node instrumentation:** log each node's *time-to-first-CMS-login* using the
  monotonic helper from the lifecycle work (`src/core/compat/lifecycle_timing.h`), e.g.
  `xrootd: CMS registered with <mgr> after N ms (attempt K)`. This is permanent,
  low-overhead, and the parse target for the harness.
- **Mesh-settle harness:** boot a multi-tier same-host mesh and time **full settle**
  = every node logged in **and** every namespace locate resolves to a redirect. This
  yields a hard before/after number and is itself a correctness check (did the whole
  mesh form?).

### Stage 2 — Fix (`src/net/cms/connect.c`, `cms_internal.h`, config)

**Adaptive fast-retry during cold startup.** Add a "have we ever logged in yet?"
notion to the CMS ctx. While a node has **never yet completed a login** and a connect
fails because the manager is **not listening yet** (`ECONNREFUSED`, and the
analogous immediate "unreachable" errno cases), retry on a short fixed interval for a
bounded window, **then** fall back to the existing exponential backoff. The
`schedule_retry` path keeps its +25% jitter for the slow-backoff regime.

**Loopback detection.** At `ngx_xrootd_cms_start`, classify `conf->cms_addr` as
loopback (`127.0.0.0/8` or `::1`) from the resolved sockaddr. Loopback gets the most
aggressive profile; remote gets a gentler one.

**Profiles (defaults — "very tight"):**

| | initial delay | fast-retry interval | fast-retry window | max attempts |
|---|---|---|---|---|
| **loopback** | 0 ms | 10 ms | 2 s | ~200 |
| **remote**   | 10 ms | 75 ms | 3 s | ~40 |

Same-host first registration then lands typically **<20 ms** after the manager's
listen socket comes up.

**Tunables (2 directives, smart defaults):**

- `xrootd_cms_connect_retry <ms>` — the fast-retry interval (overrides the profile
  default).
- `xrootd_cms_initial_delay <ms>` — delay before the first connect attempt.

### Correctness guardrails (non-negotiable)

- **No spin / no 0ms-timer footgun.** The fast-retry interval has a hard floor
  (≥10 ms) and the fast-retry phase is bounded by a window/attempt cap; after it
  expires the node falls back to exponential backoff. Because fast-retry is gated on
  *pre-first-login*, it can never run forever (login success ends it). This is the
  explicit defence against reintroducing the self-rearming-0ms-timer CPU stall from
  the idle-timer family.
- **Fast-retry is cold-start only.** A manager that connected and *then* dropped is a
  real outage → straight to exponential backoff + jitter (thundering-herd protection
  preserved). The `logged_in`-then-disconnected paths are unchanged.
- **`ngx_exiting` guards unchanged** — a draining worker never schedules a retry.
- **Wire parity untouched** — this is purely local connect *timing/policy*; no CMS
  frame, opcode, or login/handshake byte changes.

### Components / data flow

- `cms_internal.h`: ctx gains `ever_logged_in` (sticky), `fast_retry_deadline`
  (monotonic ms, 0 = not in fast-retry), and a cached `is_loopback` flag; new tunable
  fields land on the srv conf. New `#define`s for the profile constants.
- `connect.c`: `schedule_retry` consults the fast-retry state; a small helper
  `cms_classify_failure()` decides fast-retry vs backoff from the errno and
  pre-login state. `ngx_xrootd_cms_start` sets `is_loopback` and the initial delay.
- config (`server_conf.c` merge + `stream/module.c` commands): the two new
  directives.

## Testing

- **Regression:** existing mesh suites stay green — `test_cms_mesh_interop`,
  `test_conformance_topologies`, `test_e2e_cluster_matrix`, `test_chaos_mesh`,
  `test_cms_resilience`.
- **New same-host settle test:** boot a multi-tier mesh, assert full settle well
  under current timings (target sub-second for the whole mesh) and that every locate
  resolves.
- **3 per change:** fast settle (success); dead-manager → bounded backoff, no spin,
  CPU stays idle (error); flapping/hostile manager → fast-retry stays capped and
  falls back (negative).

## Results (implemented)

- **Manager already up (loopback):** `CMS registered with <mgr> after 0 ms
  (1 connect attempt, loopback)` — was a fixed ~1000 ms initial delay before.
- **Manager late (started after the node):** the node fast-retries on the 10 ms
  interval and registers within tens of ms of the manager's listen socket appearing
  — was 1 s + 2–6 s backoff.
- **Dead manager:** fast-retry stays within the 2 s window, then a single actionable
  WARN and sparse exponential backoff — no busy-spin.

**Key implementation finding:** on loopback, `connect()` to a not-yet-listening port
returns `EINPROGRESS`, so the refusal does **not** surface in the `connect()` branch
— it arrives as `recv() failed (Connection refused)` in the **read handler**
(`recv.c`), which calls `ngx_xrootd_cms_schedule_retry` directly. Routing only the
`connect()` path was therefore inert. The fix folds the fast-retry decision **into
`ngx_xrootd_cms_schedule_retry` itself**, so every caller (connect + recv) gets the
right regime automatically, gated on `ever_logged_in`.

**Tests:** `tests/test_cms_fast_settle.py` (4, self-provisioning — a plain TCP
listener is a valid manager stand-in because a node registers on TCP-connect +
send-login). Regression: `test_cms` + `test_cms_mesh_interop` +
`test_cms_state_have_select` = **52 passed** against the real cmsd fleet on loopback
(so the loopback profile is exercised against real cmsd). Note: `ngx_log_debug*` is
compiled out without `--with-debug`, so the dead-manager test observes the bounded
window via the timing/sparsity of the backoff WARN, not the (invisible) fast-retry
debug line.

## Non-goals

- No CMS wire-protocol / handshake changes.
- No change to the manager-accept/registration path.
- No new monitoring beyond the one per-node settle log line (revisit if ops want a
  metric).
- No change to the existing fast-teardown / `ngx_exiting` behaviour.
