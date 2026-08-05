# Phase-98 — CMS/AAA federation join under network noise

**Goal:** prove that a BriX data server can **join the CMS AAA federation** and
**stay joined** while the link to its redirector is being abused, and give the
operator a node-side signal that says whether it is in or out.

Two deliverables:

1. **Federation-join observability** — three new metric families so join state is
   answerable from the node's own `/metrics` (§2).
2. **An unprivileged join/noise suite** — 13 tests that put an impaired WAN
   between the node and its redirector (§3).

**Provenance:** anchors read from the tree at working state on **2026-08-05**
(post-phase-97, several waves uncommitted). Re-verify anchors at the start of
each wave and mark drift `DRIFT:` inline (phase-80 convention).

---

## 1 — What was missing

BriX already had a mature CMS stack (`src/net/cms/`, ~10.7k lines: LOGIN/HAVE/
LOAD/PING/PONG/STATE/STATUS, exponential reconnect with jitter) and heavy CMS
coverage — `test_cms_resilience.py`, `test_cms_hostile_conformance.py`,
`test_cms_wire_pup_conformance.py`, `test_cms_mesh_interop.py`, the phase-97
manager-parity work. Two gaps survived all of it:

- **No test ever put an impaired link between a node and its redirector.** Every
  existing CMS test speaks to a peer over a clean loopback socket. A real AAA
  site reaches its redirector over a WAN — latency, jitter, segmentation,
  reordering, loss, black-holes, resets. Join is a *handshake across that link*,
  and nothing exercised it as one.
- **No node-side observability for join state.** `brix_cms_read_timeouts_total`
  and `_login_timeouts_total` tell you a symptom fired; nothing told you whether
  the node is *currently registered*. During an incident that is the only
  question anyone asks, and answering it required shell access to the manager.

Neither gap is a product defect on its own, but together they mean a site could
silently fall out of the federation and nothing local would say so.

---

## 2 — Federation-join metrics

Three fields added to the Phase-51 resilience block in
`src/observability/metrics/metrics.h`:

| Metric | Type | Increments |
| --- | --- | --- |
| `brix_cms_logins_total` | counter | a LOGIN frame goes upward (one per successful join) |
| `brix_cms_connect_failures_total` | counter | an upward dial is torn down before LOGIN ever went out |
| `brix_cms_registered_links` | **gauge** | `+1` on login, `-1` on teardown — `0` means out of the cluster |

Emission is in `brix_export_resilience_metrics()`
(`src/observability/metrics/stream.c`). The two counters go through
`mw_emit_scalar`; the gauge does not, because `mw_emit_scalar` hard-codes
`# TYPE … counter`, so the gauge banner and value are written by hand with
`mw_printf` — the same pattern `frm_metrics.c` already uses. A gauge mislabelled
as a counter is worse than no metric: `rate()` on it returns nonsense and every
dashboard built on it lies.

`BRIX_RESIL_METRIC_DEC` was added to `metrics_macros.h` as the companion to the
existing INC. It is documented at the definition as gauge-only — counters must
never decrement.

### 2.1 Why the failure count lives in teardown

The obvious homes for `connect_failures_total` are the three visible failure
sites in `src/net/cms/connect.c`: the `ngx_event_connect_peer()` error branch,
the connect deadline, and the login write. All three were instrumented first,
and a refused dial still counted **zero**.

A standalone probe (a node pointed at a dead port) showed why: the log carried
`recv() failed (111: Connection refused)`, and `grep -c "will keep retrying"`
returned 0 — proving the `connect_peer` branch never ran. **On loopback, and on
any path where the peer resets rather than dropping, a refused connect surfaces
on the read side** (`cms_recv_accumulate` → `cms_conn_fail` in
`src/net/cms/recv.c`), which is a fourth site that nobody would think to
instrument.

So the count moved to `ngx_brix_cms_disconnect()`, the single funnel every
failed join passes through exactly once, as the `else` of the gauge decrement:

- `ctx->logged_in` set → this link is leaving the cluster → `DEC` the gauge.
- not set → the dial never became a link → `INC` failures.

One site, mutually exclusive branches, no double-counting regardless of which
of the four paths reported the error. The rationale is recorded in-code at the
branch, because the next person to add a failure site will otherwise repeat the
mistake.

**Correctness note.** The outbound CMS client runs on worker 0 only (stock
`cmsd` admits one connection per SID), so the gauge has exactly one writer and
needs no per-worker reconciliation. If that ever changes, the gauge becomes a
sum over workers and this assumption must be revisited.

---

## 3 — The join/noise suite

`tests/test_cms_aaa_join_noise.py` — 13 tests, entirely unprivileged, no netem,
no root, no external network.

```
  raw kXR client ──────────────► BriX node ──► brix-fault-proxy ──► ManagerPeer
   (data plane liveness)          │              (the "WAN")        (redirector
                                  │                                  stand-in)
                                  └──► HTTP /metrics ◄── scrape (the oracle)
```

The impairment is `client/bin/brix-fault-proxy` (phase-89), an unprivileged TCP
relay with a live control port: `latency`, `jitter`, `chunk`, `lossy`,
`reorder`, `corrupt`, `block`, `hang`, `truncate-at`, `replace`. That is what
makes the suite runnable as a normal user — the WAN is a userspace process, not
a kernel qdisc.

Config template `tests/configs/nginx_cms_aaa_node.conf`: a `/store` namespace
advertised upward, 1 s heartbeat, 3 s read deadline, plus an HTTP `/metrics`
listener. Ledger entry `lc-cms-aaa-node` (30509 data, 30510 metrics) in
`fleet_lifecycle_ports.py`; the proxy's listen and control ports are ephemeral,
so they are not ledgered.

`ManagerPeer` in `test_cms_resilience.py` was extended (additively) to record
every frame code in arrival order and expose `count_frames()` / `wait_frames()`.
Recording the *order* is what lets a test assert LOGIN arrived first and intact
after the link chopped and reordered it.

### 3.1 Coverage

| Class | Tests | What it proves |
| --- | --- | --- |
| `TestJoinAcrossImpairedWan` | 3 | join completes across latency+jitter; LOGIN reassembles correctly despite segmentation and reordering (`frame_codes[0] == LOGIN`); heartbeats continue under sustained noise |
| `TestOutageAndRejoin` | 5 | a silent/hung redirector drops the gauge and leaves the data plane up; a refused link counts failures on a backoff, not a hot loop (`attempts < 100` in 10 s); accept-then-close is bounded; the node rejoins when the link heals; a mid-stream sever re-registers |
| `TestHostileRedirectorAcrossLink` | 3 | corrupted downstream bytes never crash a worker; an oversized (`0xFFFF` dlen) frame is refused, not buffered; a 400-frame unsolicited storm does not starve the data plane |
| `TestDataPlaneNoise` | 2 | a 200-connection storm keeps the site registered and heartbeating; 150 connect/abort cycles leave the gauge at exactly 1 (no registration leak) |

Every test asserts on the new metrics *and* on data-plane liveness (a 20-byte
kXR handshake) *and* scans `error.log` for `exited on signal` / `SIGSEGV` /
`Assertion` — "the federation leg broke" must never mean "the site stopped
serving data", which is the whole point of a leaf node.

Module-level `pytest.mark.timeout(180)` (precedent: `test_chaos_mesh.py`) —
the 30 s default in `pytest.ini` cannot hold a test that deliberately waits out
a backoff window. `xdist_group("lc-cms-aaa-node")` serialises the group.

### 3.2 A note on `block`

`brix-fault-proxy`'s `block` lever is **accept-then-close**, not refuse — the
accept loop closes the client immediately (`client/apps/diag/brix_fault_proxy.c`).
That is a genuinely different failure mode from a refusal (an overloaded `cmsd`
behaves this way), so the suite covers both: `ImpairedLink.down()` kills the
proxy outright for true `ECONNREFUSED`, and `block` got its own test.

---

## 4 — Status

Delivered and green: 13/13 in `test_cms_aaa_join_noise.py`; no regression in
`test_cms_resilience.py`, `test_metrics.py`, `test_metrics_coverage_root.py`,
`test_cms_hostile_conformance.py`, `test_cms_wire_pup_conformance.py`; guards
`check_metric_cardinality`, `check_file_size`, `check_complexity`,
`check_template_refs`, `check_config_coverage`, `check_shm_mutex` all OK.

**Deferred:** none from this phase. Adjacent work that stays open — a live
join against a real stock `cmsd` across an impaired link (needs the k8s interop
lab, not the unprivileged local harness), and multi-manager failover ordering
under noise, which belongs with the phase-97 manager-parity track.
