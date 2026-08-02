# brix-fault-proxy — Feature-Expansion Plan (hyper-detailed)

**Status:** partially implemented (Track U wave 1 landed) · **Date:** 2026-08-01 · **Owner:** client-tooling
**Scope:** `client/apps/diag/brix_fault_proxy*.{c,h}`, `client/man/brix-fault-proxy.1`,
the Python suite (`tests/test_brix_fault_proxy.py`, `tests/test_fault_proxy_corruption.py`
+ new files below), `tests/fleet_lifecycle_ports.py`, and the three build systems
(`./config`, `client/Makefile`, RPM spec) via the `FAULT_PROXY_SRCS` list.

---

## Implementation status (2026-08-01)

**Wave 1** LANDED entirely within the existing three TUs (no new file, no CLI
flag, no libm/Makefile change). **Wave 2** adds the JSON front-end (A2+A4) as the
one new TU the plan prescribes (`brix_fault_proxy_json.c`). **Wave 3** adds the
`ctl` client subcommand (A3) as a second new TU (`brix_fault_proxy_ctl.c`).
**Wave 4** adds the JSONL fault-event log (D2) as a third new TU
(`brix_fault_proxy_event.c`). **Wave 5** upgrades `rate` to a monotonic-clock
token bucket and adds `burst` (B5) — no new TU, all within `relay.c`/`control.c`.
**Wave 6** adds named, stackable, individually-removable toxics (C1) as a fourth
new TU (`brix_fault_proxy_toxic.c`): a fixed-capacity table folded onto the flat
levers, with the relay taking the pre-C1 fast path (no lock, no compose) when the
table is empty. **Wave 7** adds dynamic multi-route on one daemon (C2) as a fifth
new TU (`brix_fault_proxy_route.c`): a fixed-capacity route table where each route
owns its own listen socket, target pool and counters, created/destroyed at runtime
via `route add|del|list`. The legacy `--listen`/`--target` pair is registered as
route `default`, so the accept plane (`fp_accept_serve`, relocated into the route
TU) treats every route uniformly; new ports bind through `fp_route_bind`, which
reuses the startup bind template so a route can never widen the loopback/insecure
gate (I4). The new-TU waves wire via the single `FAULT_PROXY_SRCS` list — the
standalone tool is not in `./config`/RPM, so each TU costs one Makefile line. Every
file stays under the 600-line guard (`.c` 560 / 568 / 429 / 386 / 274 / 223 / 214 /
112, `.h` 168). All new grammar is control-verb/JSON-only and additive; `clear`/
`reset_lever` reset the new state (including the toxic table) so tests don't leak.
The `ctl` client is read-only over the wire (no new server surface); the event log
adds no wire surface at all (an optional append-only fd guarded by one mutex, off
the per-byte hot path); the token bucket is per-connection stack state (no global
coupling) paced off `CLOCK_MONOTONIC`; the toxic table is one mutex-guarded array
composed into the relay's existing per-read lever snapshot; the route table is one
mutex-guarded array whose slots are never reused, so a relay thread may hold its
`fp_route *` for its whole lifetime with no use-after-free.

| ID | Feature | Status | Where |
|----|---------|--------|-------|
| A1 | Persistent multi-command control sessions | **LANDED** w1 | `control.c` `control_thread` line-accumulator loop (`quit`/EOF close, `err: line too long`) |
| A2 | Structured JSON control I/O | **LANDED** w2 | new `brix_fault_proxy_json.c` `brix_fp_json_request` — tiny scanner reprojects to the verb grammar + calls `apply_command` (one source of truth); `apply_command` gains a `{`-first dispatch |
| A3 | First-party `ctl` client subcommand | **LANDED** w3 | new `brix_fault_proxy_ctl.c` `fp_ctl_main`; `main()` reserves `argv[1]=="ctl"` before parsing; non-blocking dial + 3 s timeout, half-close→drain, exit 0/3/4/2 |
| A4 | `status json` machine oracle | **LANDED** w2 | `brix_fp_json_status` typed snapshot (up/down/flags/counters); `{"cmd":"status"}` returns it |
| B1 | `toxicity <pct>` per-connection affliction gate (per-direction) | **LANDED** w1 | `relay.c` `afflict_up/down` roll on a separate `tseed` RNG stream; `control.c` `toxicity` verb |
| B2 | `slow-close <ms>` delayed FIN (per-direction) | **LANDED** w1 | `relay.c` `sever()` non-abortive branch + `done:` EOF path; `slow-close` verb |
| B3 | `connect-delay`/`accept-delay <ms>` dial latency | **LANDED** w1 | `relay.c` `relay_thread` usleep after predial; `connect-delay` verb |
| B4 | `refuse <pct>` probabilistic connection drop | **LANDED** w1 | `brix_fault_proxy.c` `fp_accept_loop` refuse roll; `refuse` verb + `refused` counter |
| B5 | Token-bucket `rate` + `burst` | **LANDED** w5 | `relay.c` `fault_rate_gate` refills `tokens += elapsed*rate` (CLOCK_MONOTONIC, clamps step-back), caps at `burst_bytes` (default 1 MTU), usleeps the deficit; per-connection `rate_bucket` on the `relay_pump` stack; `burst` verb + `burst_bytes` lever |
| B6 | Latency distribution shaping (`latency-dist uniform\|normal`) | **LANDED** w1 | `relay.c` `fault_sample_jitter_ms` Irwin-Hall normal (no libm); `latency-dist` verb |
| D1 | Prometheus text-exposition `metrics` command | **LANDED** w1 | `control.c` `cmd_metrics_report` + `metrics` dispatch |
| D2 | JSONL fault-event log | **LANDED** w4 | new `brix_fault_proxy_event.c` `brix_fp_event`; `--event-log FILE` + live `event-log <path>`; relay emits sever/truncate/corrupt(batched)/dup/refuse with NO payload bytes |
| C1 | Named, stackable, individually-removable toxics | **LANDED** w6 | new `brix_fault_proxy_toxic.c` `fp_toxic_cmd`/`fp_toxic_compose`; `toxic add\|remove\|list [json]` verb; fixed `FP_MAX_TOXICS`(16) table folded onto the per-read lever snapshot; relay fast-path (no lock/compose) when `g_ntoxics==0`; `clear` empties the table |
| C2 | Dynamic multi-route on one daemon | **LANDED** w7 | new `brix_fault_proxy_route.c` `fp_route_cmd`/`fp_route_register_default` + relocated `fp_accept_serve` accept plane; `route add\|del\|list [json]` verb; fixed `FP_MAX_ROUTES`(16) table, per-route listen socket/target pool/counters; `default` route seeds `--listen`/`--target`; `fp_route_bind` reuses the vetted bind template (I4); slots never reused (no relay-thread UAF); `route del default` refused |

**Tests:** `tests/test_fault_proxy_fidelity.py` — 38 tests (`TestToxicity`,
`TestSlowClose`, `TestConnectDelay`, `TestRefuse`, `TestLatencyDist`, **`TestRate`**,
`TestPersistentSession`, `TestMetrics`, **`TestJsonControl`**, **`TestCtlClient`**,
**`TestEventLog`**) + `tests/test_fault_proxy_toxics.py` — 5 tests
(**`TestNamedToxics`**) + `tests/test_fault_proxy_routes.py` — 4 tests
(**`TestDynamicRoutes`**), each the success/error/security-neg ritual. Full fault-proxy
suite green: **65 passed** (18 existing + 47 new). Status line gained
`sclose=`/`dist=` per direction and `refuse=`/`cdelay=`/`tox=` flags; all
pre-existing status assertions preserved. JSON is a thin front-end over the newline
grammar (no lever-logic duplication); malformed JSON → `{"ok":false,"error":"parse"}`
without wedging the parser; large byte counts reproject as integers (never `%g`
scientific notation). `ctl` round-trips both grammars, half-closes so the A1 session
flushes, and maps replies to exit codes (0 ok/status · 3 err/`{"ok":false}` · 4
unreachable · 2 usage); a dead port fails closed in ~1 ms via the non-blocking dial
ceiling. The event log is JSONL, off the per-byte hot path, and provably carries no
payload bytes (only structural metadata — sever/reason, truncate cut, batched
corrupt count, dup, refuse); it fails closed at startup and on the live verb. B5
`rate` is now a per-connection token bucket (`fault_rate_gate`) with a `burst`
depth lever, paced off `CLOCK_MONOTONIC` (immune to the WSL2 backward-clock step);
throughput tests assert a broad rate band + a firm pacing lower bound rather than a
tight ±15 % that the stepping clock would flake. C1 named toxics stack a
fixed-capacity table on top of the flat levers (`fp_toxic_compose` folds each
active toxic for the direction into the relay's per-read snapshot — delays and
probabilities add, bandwidth/chunk/drip/truncate take the tightest bound); the
relay checks `g_ntoxics==0` and takes the unchanged flat fast path (no lock, no
compose) when no toxics are set, and `test_stacked_latency_is_additive` proves two
same-type toxics compose where the flat single-field lever could hold only one. C2
dynamic routes let one daemon host many named proxies created at runtime, each with
its own listen socket, target pool and counters; `test_route_relays_with_independent_counters`
drives traffic through a runtime-added route and confirms `route list json` accounts
it on that route's own counters (the default route carries none), `route del` frees
the port for re-binding, and the security-neg proves the control plane refuses
`route del default` (which would wedge the daemon) while a dynamic route inherits
the loopback bind rather than widening it.

**Deferred** (high-risk structural, not yet): none in Track U — A/B/C/D all landed.
**Track R** (R1 netem …
R5 EDT) remains root-only and unverifiable as an unprivileged user; R4
evaluate-only.

---

## Table of contents

- [0. Purpose, invariants, non-goals](#0-purpose-invariants-non-goals)
- [1. Current-state reference (as-built)](#1-current-state-reference-as-built)
- [2. Track U — userspace (root-free) roadmap](#2-track-u--userspace-root-free-roadmap)
  - [Phase A — control-plane ergonomics](#phase-a--control-plane-ergonomics)
  - [Phase B — fault fidelity](#phase-b--fault-fidelity)
  - [Phase C — named toxics + dynamic routes](#phase-c--named-toxics--dynamic-routes)
  - [Phase D — observability](#phase-d--observability)
- [3. Track R — root-mode expansion](#3-track-r--root-mode-expansion)
- [4. Consolidated test matrix](#4-consolidated-test-matrix)
- [5. Build integration (three build systems)](#5-build-integration-three-build-systems)
- [6. Port allocation](#6-port-allocation)
- [7. Sequencing & acceptance gates](#7-sequencing--acceptance-gates)
- [8. Risk register](#8-risk-register)
- [9. Rejected features (non-goals, with rationale)](#9-rejected-features-non-goals-with-rationale)

---

## 0. Purpose, invariants, non-goals

`brix-fault-proxy` is a **root-free, protocol-agnostic L4 fault injector**: a
thread-per-connection TCP relay (`brix_fault_proxy_relay.c`) driving per-direction
byte levers, a newline control port (`brix_fault_proxy_control.c`), and a
CLI/lifecycle core (`brix_fault_proxy.c`), with shared state in
`brix_fault_proxy_internal.h`. It sits *below* the application protocol, which is
exactly why it works identically in front of raw `root://` binary, WebDAV, S3 and
gsiftp endpoints.

A gap analysis against the two neighbouring tool classes — **L4 chaos proxies**
(Toxiproxy · Muxy · Blockade) and **L7 intercepting proxies** (mitmproxy · Burp ·
ZAP) — drives this plan. It separates *build-worthy* extensions (things that
extend the tool along its own grain) from *deliberate non-goals* (§9), and adds a
privileged **root-mode track** (§3) for packet-level and topology faults that pure
userspace fundamentally cannot reach.

### Invariants (must survive every change)

| # | Invariant | Enforced at |
|---|-----------|-------------|
| I1 | **Root-free by default.** The unprivileged path stays fully functional and default; every privileged feature is opt-in and off unless requested. | `main()` — no `euid` sniffing; privileged code only reachable via explicit `--flag`. |
| I2 | **Protocol-agnostic core.** The default data plane never parses application protocol. TLS/protocol awareness is opt-in root-mode only, never required for byte levers. | `brix_fault_proxy_relay.c` stays byte-only; any parsing lives in a separate opt-in TU. |
| I3 | **Deterministic + reproducible.** All randomness is per-thread `rand_r()` seeded from `--seed` + conn id (`relay.c:390`). New probabilistic levers inherit this seeding. | Every `rand_r(seed)` call threads the per-relay `seed`. |
| I4 | **Control port loopback-gated + fail-closed.** The `--insecure-bind` gate (`main.c:447`, `fp_setup_bind`) is not weakened; new remote-reachable surfaces (JSON, `/metrics`, routes) inherit it. | `fp_setup_bind()` remains the single bind gate. |
| I5 | **No wire break.** New control verbs are additive; existing flat levers remain the backward-compatible "default toxic". Existing scripts and tests keep working unchanged. | `apply_command()` short-circuit chain — new handlers append, never replace. |
| I6 | **House rules.** No `goto`; functional/early-return; reuse helpers; files **≤600 lines** (guard) → new capability = **new TU**; **3 tests per change** (success + error + security-negative). | file-size guard, `check_brix_namespace.py`, CI. |

Non-goals are enumerated with rationale in [§9](#9-rejected-features-non-goals-with-rationale).

---

## 1. Current-state reference (as-built)

Self-contained snapshot so the deltas below are unambiguous. Line references are
to the files as they stand on 2026-08-01.

### 1.1 Shared state (`brix_fault_proxy_internal.h`)

```c
typedef struct {                 /* per-direction lever, 0 = off */
    volatile int  latency_ms, jitter_ms, chunk_bytes, drip_bytes, drip_ms;
    volatile int  rate_kbps;     /* KB/s, paced                        */
    volatile int  lossy_ppm;     /* per-chunk sever prob, ppm (1%=10000)*/
    volatile int  reorder_ppm;   /* per-chunk hold-back prob, ppm       */
    volatile int  reorder_ms;    /* hold-back delay (default 50)        */
    volatile int  corrupt_ppm;   /* per-byte bit-flip prob, ppm         */
    volatile int  dup_ppm;       /* per-chunk duplicate prob, ppm       */
    volatile long truncate_at;   /* sever after N bytes this dir; 0=off */
} lever_t;
extern volatile lever_t g_up, g_down;

typedef struct { char host[256]; int port; } fp_target;
extern fp_target g_targets[FP_MAX_TARGETS /*8*/]; extern int g_ntargets; extern unsigned g_rr;

extern volatile int      g_blocked, g_hang, g_abortive, g_one_shot, g_fail_nth;
extern volatile unsigned g_drop_epoch, g_halfclose_epoch;
extern unsigned          g_seed; extern int g_max_conns;

typedef struct { unsigned long conns, active, up_bytes, down_bytes,
                               severs, corrupt, dups, refused; } fp_counters;
extern fp_counters C;                 /* CBUMP/CDEC/CBUMP2 = __atomic_* RELAXED */

typedef struct { int client_fd; unsigned epoch; unsigned long conn_id; } relay_arg;
```

### 1.2 Control grammar (`apply_command`, `control.c:222`)

Verb + args; a short-circuit chain of `cmd_set_lever` → `cmd_set_epoch` →
`cmd_set_misc` → `status`. Directional levers strip a trailing `up|down|both`
token via `dir_of()` (`control.c:39`) and fan out with `SET_DIR`.

- **levers:** `latency jitter chunk rate` `<n>`; `drip <bytes> <ms>`;
  `lossy corrupt dup <pct>`; `reorder <pct> [ms]`; `truncate-at <bytes>`.
- **epoch/lifecycle:** `drop reset half-close hang unhang block unblock`.
- **misc:** `fail-nth <n>` `heal-after <ms>` `one-shot` `abortive <0|1>` `clear`.
- **query:** `status`.

**Transport:** `control_thread` (`control.c:242`) accepts, `read()`s **once**
(≤255 B), applies one command, writes the reply, **closes** (one command per TCP
connection). `--script FILE` replays `<seconds> <command>` lines (`script_thread`).

### 1.3 CLI (`main.c`)

`fp_config{listen_port, control_port, bind_str, script_path, insecure, quiet}`.
Long-opt codes: latency 1000, jitter 1001, chunk 1002, drip 1003, lossy 1004,
reorder 1005, block 1006, corrupt 1007, dup 1008, rate 1009, truncate-at 1010,
fail-nth 1011, heal-after 1012, hang 1013, seed 1014, max-conns 1015, script 1016.
`fp_setup_bind` enforces the loopback gate; `fp_accept_loop` checks `g_blocked` /
`g_max_conns`, sets `TCP_NODELAY`, spawns a detached `relay_thread` per accept.

### 1.4 Data plane (`relay.c`)

`relay_thread` → `relay_predial` (fail-nth / hang) → `dial_any` (round-robin
failover) → `relay_pump` (poll loop, 64 KiB buf, half-close via
`g_halfclose_epoch`). Per read: `forward_faulted` snapshots levers once
(`relay.c:240`), computes `piece` (drip?chunk?whole), applies `latency`, then
loops `forward_segment` = clamp (`fault_clamp_seg`, truncate) → delays
(`fault_delays`: jitter/reorder/rate `usleep`) → lossy sever → corrupt
(`fault_corrupt`) → `write_all` → dup. Severs via `sever()` (SO_LINGER RST when
abortive), honouring `one-shot`.

---

## 2. Track U — userspace (root-free) roadmap

Ordered value ÷ effort. Each item below carries a full spec: **Problem · Surface
· Data delta · Integration · Compat/edge · Tests**. Effort key: S ≤½ day,
M 1–2 days, L 3–5 days.

### Phase A — control-plane ergonomics

The control plane is one-command-per-connection, unstructured, `nc`-driven. These
four items close most of Toxiproxy's usability edge without a REST server.

---

#### A1 · Persistent multi-command control sessions — S · **LANDED 2026-08-01**

**Problem.** `control_thread` (`control.c:257`) `read()`s once then `close()`s, so
every command pays a fresh TCP handshake and a REPL is impossible.

**Surface.** No new verbs. The socket now reads newline-delimited commands in a
loop until EOF/`quit`. Backward-compatible: a client that sends one line and
half-closes still gets exactly one reply.

**Data delta.** None. Add a line-buffered reader loop.

**Integration.** Replace the single `read()` in `control_thread` with a small
line-accumulator:

```c
/* pseudocode — control.c */
char buf[1024]; size_t used = 0;
for (;;) {
    ssize_t n = read(cfd, buf + used, sizeof(buf) - 1 - used);
    if (n <= 0) break;                       /* EOF / peer close */
    used += (size_t) n; buf[used] = '\0';
    char *nl, *start = buf;
    while ((nl = memchr(start, '\n', used - (start - buf)))) {
        *nl = '\0';
        if (strcmp(start, "quit") == 0) { close(cfd); return; }
        char reply[768]; apply_command(start, reply, sizeof reply);
        if (write_all(cfd, reply, (ssize_t) strlen(reply)) != 0) { close(cfd); return; }
        start = nl + 1;
    }
    memmove(buf, start, used -= (start - buf));   /* keep partial line */
    if (used >= sizeof(buf) - 1) { /* overlong line */ used = 0; }
}
```

**Compat/edge.** Overlong (>1 KiB) line dropped with `err: line too long`;
`quit`/EOF closes cleanly; partial line across reads preserved via `memmove`.

**Tests (`test_brix_fault_proxy.py`).**
- success: one socket sends `corrupt 0.5 down\n` then `status\n` then `quit\n`;
  assert two replies received, `status` reflects the earlier `corrupt`.
- error: send a 2 KiB line with no newline → `err: line too long`, process alive,
  next command on the same socket still works.
- security-neg: session socket still bound to loopback; a `--bind 0.0.0.0`
  start without `--insecure-bind` refuses to launch (gate unchanged).

---

#### A2 · Structured JSON control I/O — M · **LANDED 2026-08-01**

**Problem.** Replies are human strings; there are no language bindings, so callers
regex `nc` output. Toxiproxy ships a JSON API + clients.

**Surface.** A control line whose first non-space byte is `{` is parsed as JSON.
Request/response schemas:

```jsonc
// request
{ "cmd": "corrupt", "pct": 0.01, "dir": "down" }         // any lever
{ "cmd": "drip", "bytes": 4096, "ms": 20, "dir": "up" }
{ "cmd": "status", "format": "json" }
{ "cmd": "clear" }
// response (non-status)
{ "ok": true }
{ "ok": false, "error": "unknown command" }
// response (status)
{ "up":   { "latency_ms":0, "corrupt_pct":0.01, ... },
  "down": { ... },
  "flags":{ "blocked":false, "hang":false, "abortive":false,
            "one_shot":false, "fail_nth":0, "epoch":3 },
  "counters":{ "conns":12,"active":1,"up_bytes":40960,"down_bytes":8192,
               "severs":2,"corrupt":17,"dups":0,"refused":1 } }
```

**Data delta.** None to the levers. A new TU keeps `control.c` under the 600-line
guard.

**Integration.** New TU `brix_fault_proxy_json.c` exporting:

```c
int  brix_fp_json_request(const char *line, char *out, size_t osz); /* 1=handled JSON */
void brix_fp_json_status(char *out, size_t osz);                    /* status snapshot */
```

`apply_command` gains a first branch: `if (line[i]=='{') return brix_fp_json_request(...)`.
The parser is a **tiny, dependency-free** scanner (the client tree has no JSON
lib): it extracts `cmd`/`dir`/numeric scalars, reprojects to the existing verb
string, and calls `apply_command` internally, so JSON is a thin front-end over the
one grammar (no duplicate lever logic → no drift).

**Compat/edge.** Non-JSON lines fall through to the newline grammar unchanged.
Malformed JSON → `{"ok":false,"error":"parse"}`, process survives, subsequent
lines still parse. Numeric overflow clamped as the existing `atoi`/`strtod` paths do.

**Tests (`test_brix_fault_proxy.py` — new `TestJsonControl`).**
- success: `{"cmd":"corrupt","pct":0.02,"dir":"down"}` → `{"ok":true}`, then
  `{"cmd":"status","format":"json"}` parses as JSON with `down.corrupt_pct==0.02`.
- error: `{"cmd":` (truncated) → `{"ok":false,"error":"parse"}`; newline command
  on the next line still works (grammar not wedged).
- security-neg: JSON path honours the bind gate (covered by A-shared gate test);
  an unknown `cmd` yields `{"ok":false,"error":"unknown command"}`, no state change.

---

#### A3 · First-party `ctl` client subcommand — S · **LANDED 2026-08-01**

**Problem.** Operators/tests shell out to `nc -q1`, a non-portable dependency.

**Surface.**
```
brix-fault-proxy ctl <host:port> "<command>"     # sends one command, prints reply
brix-fault-proxy ctl <host:port> -               # reads commands from stdin (REPL/batch)
```
Round-trips both grammars (A1 session, A2 JSON). Exit 0 on `ok`/`status`, 3 on
`err:`/`{"ok":false}` (scriptable).

**Data delta.** None.

**Integration.** In `main()`/`fp_parse_args`, detect `argv[1]=="ctl"` **before**
option parsing and dispatch to a new `fp_ctl_main(argc, argv)` (new TU
`brix_fault_proxy_ctl.c`): dial, write command(s), read to EOF, print, map reply
→ exit code. Reuses `dial()`? No — `dial()` is `relay.c` static; add a local
minimal connect. Keeps the fault-proxy server code untouched.

**Compat/edge.** `ctl` is a reserved first-arg; it never collides with the
positional `LISTEN HOST PORT CONTROL` form (that form has 4 numeric-ish args, not
the literal `ctl`). Connection refused → exit 4 with a clear message.

**Tests (`test_brix_fault_proxy.py` — `TestCtlClient`).**
- success: start a proxy, `ctl 127.0.0.1:<ctl> "status"` prints a status line,
  exit 0.
- error: `ctl 127.0.0.1:<ctl> "bogus"` → prints `err: unknown command`, exit 3.
- security-neg: `ctl` to a dead port → exit 4, no hang (connect timeout enforced).

---

#### A4 · `status json` machine oracle — S (folds into A2) · **LANDED 2026-08-01**

Delivered by A2's `brix_fp_json_status`. Tracked separately only so tests can
assert on fields rather than regex the human `cmd_status_report` string
(`control.c:200`). No extra code beyond A2.

---

### Phase B — fault fidelity

New primitives inside the L4 byte model. All inherit I3 (seeded RNG).

---

#### B1 · `toxicity <pct>` — per-connection affliction fraction — S · **LANDED 2026-08-01**

**Problem.** Levers apply to **all** connections. Toxiproxy can afflict a
*fraction* of connections; the current tool cannot express "corrupt 30% of
sessions, leave the rest clean."

**Surface.** `toxicity <pct> [up|down|both]` (0–100, default 100 = current
behaviour). A per-direction gate probability.

**Data delta.**
```c
/* internal.h — new global, mirrors g_up/g_down pattern */
extern volatile int g_toxicity_up_ppm, g_toxicity_down_ppm; /* default 1000000 = 100% */
/* relay_arg gains a per-direction afflicted flag decided once at accept */
typedef struct { int client_fd; unsigned epoch; unsigned long conn_id;
                 unsigned char afflict_up, afflict_down; } relay_arg;
```

**Integration.** In `fp_accept_loop` (or top of `relay_thread`, after seed is
known), roll once per direction with the relay's seed:
`ra->afflict_up = (rand_r(&s) % 1000000u) < g_toxicity_up_ppm;`. In
`relay_pump_dir`, if the direction is not afflicted, pass bytes through with **no**
lever application (fast path). Determinism: roll uses `g_seed + conn_id*K` so a
seeded run reproduces which connections are afflicted.

**Compat/edge.** Default 100% ⇒ byte-identical to today. `toxicity 0` = a clean
pass-through even with other levers armed (useful A/B control arm).

**Tests (new `tests/test_fault_proxy_fidelity.py` — `TestToxicity`).**
- success: `corrupt 100 down` + `toxicity 100 down` over N conns → all corrupted;
  `toxicity 0 down` → none corrupted despite `corrupt 100`.
- error: `toxicity 150` clamped to 100 (or `err:`), state consistent.
- security-neg: control port reachable while `toxicity` armed; seeded run
  reproduces the exact afflicted-connection set across two runs (determinism).

---

#### B2 · `slow-close <ms>` — delayed FIN — S · **LANDED 2026-08-01**

**Problem.** No delayed-close primitive (Toxiproxy `slow_close`); clients that
depend on prompt teardown are never exercised.

**Surface.** `slow-close <ms> [dir]` — after EOF/sever on the named direction,
`usleep(ms)` before `close()`.

**Data delta.** `lever_t` gains `volatile int slow_close_ms;` (reset in
`reset_lever`, printed in status).

**Integration.** In `sever()` and the EOF `done:` path of `relay_pump`
(`relay.c:374`), honour `slow_close_ms` before the `close()`. Applies to the
direction whose lever is set (both sockets close, but the FIN on `to` is delayed).

**Compat/edge.** 0 = today's immediate close. Interacts with `abortive`: RST +
slow-close is contradictory → RST wins, `slow-close` ignored when `abortive` (doc
this; status shows both).

**Tests (`test_fault_proxy_fidelity.py` — `TestSlowClose`).**
- success: `slow-close 300 down` → client observes ≥~250 ms between last byte and
  FIN.
- error: `slow-close -1` → `err:`, lever unchanged.
- security-neg: slow-close does not block the accept/control threads (a second
  connection is served during the delay — thread-per-conn proven).

---

#### B3 · `accept-delay` / `connect-delay <ms>` — establishment latency — S · **LANDED 2026-08-01**

**Problem.** `latency` delays *chunks*; nothing models slow **connection setup**
(SYN→ACK / upstream dial latency), a distinct client-timeout surface.

**Surface.** `connect-delay <ms>` — after accept, before `dial_any()`, `usleep`.
(`accept-delay` alias.) Global (connection-scoped), not per-direction.

**Data delta.** `extern volatile int g_connect_delay_ms;`

**Integration.** In `relay_thread`, between `relay_predial` and `dial_any`
(`relay.c:392-396`), `if (g_connect_delay_ms) usleep(...)`.

**Compat/edge.** Composes with `hang`/`fail-nth` (those short-circuit before the
delay). 0 = today.

**Tests (`test_fault_proxy_fidelity.py` — `TestConnectDelay`).**
- success: `connect-delay 400` → measured time-to-first-byte ≥ ~350 ms; steady
  chunk latency unaffected.
- error: `connect-delay -5` → `err:`.
- security-neg: a client that gives up during the delay is cleaned up (no fd/thread
  leak — assert `active` returns to baseline via `status`).

---

#### B4 · `refuse <pct>` — probabilistic connection refusal — S · **LANDED 2026-08-01**

**Problem.** New-connection failure is all-or-nothing (`block`) or exact-index
(`fail-nth`); no *probabilistic* refusal (flaky listener).

**Surface.** `refuse <pct>` (0–100). Independent of `block`.

**Data delta.** `extern volatile int g_refuse_ppm;`

**Integration.** In `fp_accept_loop` (`main.c:474`), after the `g_blocked` check:
roll with a loop-local seed; on hit `CBUMP(refused,1); close(client); continue;`.

**Compat/edge.** `refuse 100` ≈ `block` for *new* conns but (unlike `block`) does
not sever live ones and does not bump `g_drop_epoch`.

**Tests (`test_fault_proxy_fidelity.py` — `TestRefuse`).**
- success: `refuse 100` → all new connects refused, `refused` counter climbs, live
  conn (opened before) keeps flowing.
- error: `refuse 200` clamped/`err:`.
- security-neg: control port itself is never subject to `refuse` (it is a separate
  listener — assert control still answers while `refuse 100`).

---

#### B5 · Token-bucket `rate` + `burst` — S/M · **LANDED 2026-08-01**

**Problem.** `rate` today is a per-segment `usleep` in `fault_delays`
(`relay.c:163`): bursty, inaccurate at small segments, ignores accumulated credit.

**Surface.** `rate <KB/s> [dir]` (unchanged verb) now backed by a token bucket;
new optional `burst <bytes> [dir]` sets bucket depth (default = one MTU, ~1500 B,
preserving today's near-behaviour).

**Data delta.** `lever_t` gains `volatile int burst_bytes;` plus per-relay bucket
state (tokens + last-refill timestamp) held **on the stack** in `relay_pump`
(not global — avoids cross-connection coupling). Timestamp via
`clock_gettime(CLOCK_MONOTONIC)` (no `Date.now()` concerns — this is C runtime).

**Integration.** Replace the `rate_kbps` branch of `fault_delays` with a
`fault_rate_gate(seg, &bucket, L)` that refills `tokens += elapsed * rate`, caps at
`burst`, and `usleep`s only for the deficit. Per-direction buckets live in
`relay_pump`'s frame, passed down through `forward_faulted`→`forward_segment`.

**Compat/edge.** Default burst = MTU ⇒ throughput within tolerance of the old path
but smoother. `rate 0` disables (today). Precision bounded by `usleep` (~1 ms).

**Tests (`test_fault_proxy_fidelity.py` — `TestRate`).**
- success: transfer M bytes at `rate 512` → measured throughput within ±15 % of
  512 KB/s; `burst 65536` lets a short transfer complete faster (credit).
- error: `burst -1` / `rate -1` → `err:`.
- security-neg: rate gate uses monotonic clock (immune to the known WSL2 backward
  clock step, `[[wsl2-clock-backwards-steps]]`); the observable safety property is
  bounded completion — a rated transfer always finishes and never wedges the relay
  (true clock-step injection needs privilege/a fake clock, so the monotonic clamp
  itself is verified by inspection of `fault_rate_gate`).

---

#### B6 · Latency distributions — M · **LANDED 2026-08-01**

**Problem.** `jitter` is uniform `0..ms` (`relay.c:158`). Real RTT variance is
normal/pareto-shaped; netem models this with `distribution normal|pareto`.

**Surface.** `latency-dist uniform|normal|pareto <mean_ms> [sigma_ms] [dir]`. Sets
a per-direction distribution used by the jitter/latency delay.

**Data delta.** `lever_t` gains `volatile int lat_dist; /* 0 uniform 1 normal 2 pareto */`
and `volatile int lat_sigma_ms;`.

**Integration.** New `fault_sample_delay(const lever_t*, unsigned *seed)` returns a
sampled millisecond delay: uniform (today), normal (Box–Muller with `rand_r`,
clamped ≥0), pareto (inverse-CDF). Called from `fault_delays`/`forward_faulted`
in place of the raw `jitter` usleep.

**Compat/edge.** `uniform` = today. Negative samples clamped to 0. Sigma default =
mean/4.

**Tests (`test_fault_proxy_fidelity.py` — `TestLatencyDist`).**
- success: over many seeded chunks, `latency-dist normal 100 20` yields a
  sample mean within ±10 ms of 100 and non-zero variance (histogram assertion).
- error: `latency-dist bogus` → `err:`, distribution unchanged.
- security-neg: seeded distribution is reproducible (two runs, identical sample
  sequence) — protects I3.

---

### Phase C — named toxics + dynamic routes

The two structural Toxiproxy gaps. Highest risk (they touch the lever model and
the accept model), so they land after A/B harden the grammar/tests.

---

#### C1 · Named, stackable, individually-removable toxics — L · **LANDED 2026-08-01**

**Problem.** Levers are single global fields, so you cannot stack two of the same
type or remove one by name. Toxiproxy models a *list* of named toxics per
direction.

**Surface.**
```
toxic add  <name> <type> <params…> [up|down|both]   # e.g. toxic add slowdl latency 200 down
toxic remove <name>
toxic list [json]
```
Types reuse the existing lever vocabulary (latency/jitter/chunk/drip/rate/lossy/
reorder/corrupt/dup/truncate/slow-close).

**Data delta.** New `brix_fault_proxy_toxic.c` + a small fixed-capacity table
(no malloc on the hot path):
```c
#define FP_MAX_TOXICS 16
typedef struct { char name[32]; int type; int dir; lever_t vals; int active; } fp_toxic;
extern fp_toxic g_toxics[FP_MAX_TOXICS]; extern int g_ntoxics;
```
The existing flat `g_up`/`g_down` remain the implicit **default toxic** (index 0
semantics), so nothing breaks.

**Integration (as built).** `forward_faulted` takes its usual once-per-read
`lever_t snap = *L;` snapshot, **then** — guarded by `if (g_ntoxics > 0)` before any
lock — calls `fp_toxic_compose(&snap, dir_i)` (dir_i 0=up/1=down), which under one
mutex folds every active toxic for that direction into the snapshot: delays and
probabilities **add** (probabilities clamped to 100%), while bandwidth/chunk/drip/
truncate take the **tightest** (min non-zero) bound. When `g_ntoxics==0` the relay
takes the pre-C1 flat fast path unchanged — no lock, no compose, zero overhead. The
existing flat `g_up`/`g_down` remain the implicit **default toxic**, so nothing that
pre-dates C1 changes. Direction match uses the `dir_of` convention (0 both / 1 up /
2 down) against the relay's `dir_i`. Table mutation (add/remove/compose) is
serialised by the same mutex; `remove` compacts the array so live toxics stay dense.

**Compat/edge.** Duplicate name → `err: exists`; unknown name on remove →
`err: no such toxic`; table full → `err: too many toxics`; unknown type →
`err: unknown toxic type`; unknown subcommand → `err: unknown toxic subcommand`.
`clear` (and `clear_all`) empties the toxic table via `fp_toxic_clear()`.

**Tests (new `tests/test_fault_proxy_toxics.py` — `TestNamedToxics`, 5 tests).**
- success: `test_add_list_remove_lifecycle` (add two, `toxic list` text+json reflect
  them, remove one, `clear` empties); `test_toxic_composes_into_relay` (a `latency`
  toxic delays the relayed stream and remove restores the fast path);
  `test_stacked_latency_is_additive` (two `latency 150 down` toxics compose to
  ≥0.25 s of delay — impossible for the single flat lever, proving stacking).
- error: `test_bad_inputs_rejected` — duplicate name / unknown type / unknown
  subcommand / `toxic remove ghost` all reply `err:` and leave the table unchanged.
- security-neg: `test_capacity_capped_and_clear_suppresses` — the 17th add is refused
  (`err: too many toxics`) with the table staying exactly full (fixed capacity, no
  overrun), and `clear` restores the flat fast path (a post-clear transfer is fast).

**Deviation from the sketch above.** The pre-implementation note proposed
snapshotting "a slice pointer"; the built version instead re-locks inside
`fp_toxic_compose` and folds under the mutex — simpler and race-free, and the
`g_ntoxics>0` guard still keeps the empty-table fast path lock-free.

---

#### C2 · Dynamic multi-route on one daemon — L · **LANDED 2026-08-01**

**Problem.** One process = one listen→target path fixed at launch. Toxiproxy runs
many named proxies in one server, created/destroyed at runtime.

**Surface.**
```
route add  <name> <listen_port> <target_host:port[,host:port…]>
route del  <name>
route list [json]
```
Each route owns its own listen thread + target pool + counters (and, post-C1, its
own toxic table).

**Data delta.** New `brix_fault_proxy_route.c`:
```c
#define FP_MAX_ROUTES 16
typedef struct { char name[32]; int listen_fd; int listen_port;
                 fp_target targets[FP_MAX_TARGETS]; int ntargets;
                 fp_counters counters; pthread_t accept_tid; volatile int stop; } fp_route;
```
This generalises today's single global path; the legacy `--listen/--target` becomes
route `"default"`. Existing globals (`g_targets`, `C`) become the default route's
fields (kept as externs for source compatibility during migration).

**Integration.** `route add` binds via the existing `listen_sa`/`fp_setup_bind`
gate (I4), spawns an accept thread reusing `fp_accept_loop` parameterised by
route. `route del` sets `stop`, closes the listen fd, joins. The current
`fp_accept_loop` is refactored to take a route context instead of reading globals.

**Compat/edge.** `route add` on a bound port → `err: port in use`, existing routes
untouched. Non-loopback listen without `--insecure-bind` → refused (I4). Deleting
`default` is allowed but warned.

**Tests (`tests/test_fault_proxy_routes.py`).**
- success: start with one route, `route add r2 <p2> <target>` at runtime, drive
  traffic through r2, `route list json` shows both with independent counters;
  `route del r2` frees the port (re-bind succeeds).
- error: `route add r3 <p2-inuse> …` → `err: port in use`; `route del ghost` →
  `err:`.
- security-neg: `route add r4 <p> …` with a non-loopback bind + no
  `--insecure-bind` → refused; per-route control never widens the bind gate.

**As built (2026-08-01).** New TU `brix_fault_proxy_route.c` (386 lines) defines
`fp_route g_routes[16]`/`g_nroutes` under one mutex; `fp_route` carries
`name/listen_fd/listen_port/targets/ntargets/rr/counters/tid/stop/is_default/active`.
The accept plane `fp_accept_serve` was **relocated here** from `brix_fault_proxy.c`
(which fell to 560 lines) so the route TU owns all accepting — the default route
drives it on the main thread (blocking `accept`), each dynamic route on its own
`route_accept_thread` (polls `stop` every 200 ms so `route del` unwinds promptly).
`fp_route_register_default` seeds `g_routes[0]` from `g_targets`/`g_ntargets` as
route `default`. `route add` binds via `fp_route_bind` (reuses the startup
`g_bind_tmpl`, so a route inherits the vetted loopback/insecure gate and can never
widen it — I4), then spawns the accept thread. `route del` sets `stop`, joins the
thread, then closes the fd **after** the join (never races a live `accept`), and
marks the slot `active=0`.

**Deviations from the plan.**
- **Fault levers + toxic table stay process-global** (shared by every route), not
  per-route — the plan's "post-C1, its own toxic table" is left as future work.
  Only targets, counters and lifecycle are per-route.
- **Slots are never reused for a *live* route after retirement without
  quiescing**: `route del` joins the accept thread before freeing, and the slot is
  only re-`add`-able once `active==0`. Because slots are never freed/compacted, a
  relay thread may hold its `fp_route *` for its whole lifetime with no
  use-after-free (the cap is 16 concurrent, matching `FP_MAX_ROUTES`).
- **Counters are per-route `conns`/`up_bytes`/`down_bytes`** (bytes folded from the
  relay's per-direction totals at connection teardown via a `ROUTE_FOLD` macro in
  `relay.c`); the global `C` remains the aggregate oracle for `status`/`metrics`.
- **`route del default` is refused** (`err: cannot delete default route`) rather
  than "allowed but warned" — deleting the primary listener would wedge the daemon,
  so the safer refusal was chosen. Non-loopback bind refusal is enforced structurally
  by `fp_route_bind` reusing the vetted template, so no per-route bind-string is
  even parsed (a route physically cannot widen the gate).

---

### Phase D — observability

---

#### D1 · Prometheus text exposition — S/M · **LANDED 2026-08-01**

**Surface.** New verb `metrics` returns Prometheus text; when a route/HTTP-style
control is active, `GET /metrics\r\n\r\n` on the control port returns the same.
```
brix_fault_proxy_conns_total{route="default"} 12
brix_fault_proxy_bytes_total{route="default",dir="up"} 40960
brix_fault_proxy_severs_total{route="default"} 2
brix_fault_proxy_corrupt_bytes_total{route="default"} 17
brix_fault_proxy_active_conns{route="default"} 1
```

**Integration.** New `brix_fp_metrics_render(char *out, size_t)` in
`brix_fault_proxy_json.c` (or a `_metrics.c` if it pushes `json.c` over 600 lines),
walking per-route `fp_counters`. Low-cardinality labels only (route, dir) —
mirrors project INVARIANT 8.

**Tests (`test_brix_fault_proxy.py` — `TestMetrics`).**
- success: after a `drop`, scraping `metrics` shows `severs_total` incremented.
- error: `GET /wrong` → `404`-style `err:`, process alive.
- security-neg: `/metrics` honours the loopback gate (no exposure via
  non-loopback bind without the insecure flag).

---

#### D2 · JSONL fault-event log — S · **LANDED 2026-08-01**

**Surface.** `--event-log FILE` (and live `event-log <path>`): append one JSON
object per fault event.
```jsonc
{"t":1722470400.12,"route":"default","conn":42,"dir":"down","event":"sever","reason":"lossy"}
{"t":1722470400.13,"route":"default","conn":42,"dir":"down","event":"truncate","at":5242880}
```
Events: `sever` (reason lossy|truncate|drop|reset|write-error), `corrupt` (batched
count per read), `dup`, `refuse`. **No payload bytes** are ever logged (capture
stays a non-goal, §9).

**Data delta.** A single append-only fd + a mutex (writes are rare, off the
per-byte hot path — only fired on discrete events).

**Integration.** `fault_sever`, `fault_corrupt` (batched), the `dup` branch, and
`fp_accept_loop` refuse path emit via `brix_fp_event(route, conn, dir, ev, …)`.
Guarded by a NULL fd check so it is zero-cost when `--event-log` is unset.

**Tests (`test_brix_fault_proxy.py` — `TestEventLog`).**
- success: with `--event-log`, a `truncate-at` cut produces a `"event":"truncate"`
  JSONL line with the right `at`.
- error: unwritable path → clean startup failure (exit 1), not a crash; live
  `event-log /no/such/dir` → `err:`.
- security-neg: log lines contain **no payload bytes** (assert the corrupted
  content never appears in the log) — confirms the capture non-goal holds.

---

## 3. Track R — root-mode expansion

The default is root-free (I1); this is a strict, opt-in **superset** unlocking
faults userspace cannot model. **Every R item is gated identically:**

- **Off unless an explicit flag requests it** (`--netem IFACE`, `--transparent`,
  `--partition SPEC`, `--tls-intercept`). Never auto-enabled by `euid==0`.
- **Fail closed** if the required capability is missing (clear message; install
  nothing; never silently downgrade to the userspace approximation).
- **Revert all kernel/system state on exit** — atexit + SIGINT/SIGTERM handler —
  and a `brix-fault-proxy --cleanup <tag>` escape hatch for crash recovery. Every
  rule/qdisc/link is **tagged** (`brixfp-<pid>` or a user `--tag`) so cleanup is
  scoped and never touches unrelated config.
- **Named resources only:** operate solely on interfaces/namespaces explicitly
  named on the command line; never a wildcard/default device.
- **Control port stays loopback-only under root** (the blast radius of an
  unauthenticated privileged control plane is worse); `--insecure-bind` is refused
  when any R feature is active.

---

### R1 · Kernel `tc netem` backing — M — *headline root-mode win*

**Problem.** The userspace core honestly cannot do sub-TCP faults: "loss" is a
sever, "reorder" is a hold-back, true packet corruption below the TCP checksum is
impossible. netem does all of these — but needs `CAP_NET_ADMIN`.

**Surface.** `--netem IFACE` enables a netem-backed lever set; the **same control
grammar** drives it (a `netem` route/prefix selects the qdisc path). Mapped
faults: `loss`, `duplicate`, `corrupt`, `reorder`, `delay … distribution`.

**Mechanism.** Program and tear down a `netem` qdisc, e.g.:
```
tc qdisc add dev IFACE root netem \
   delay 100ms 20ms distribution normal loss 1% duplicate 0.5% corrupt 0.1% reorder 25% 50%
# on any lever change: tc qdisc change …   ; on exit: tc qdisc del dev IFACE root
```
Executed via `fork`+`execvp` of `tc` (present on any CAP_NET_ADMIN host) — no
netlink dependency in v1. Capability probed up front via `capget`/a dry-run;
missing ⇒ fail closed.

**Compat/edge.** netem levers are packet-layer and **whole-interface**, so they
coexist with — and are distinct from — the per-connection userspace levers; docs
must make the "interface-wide, below TCP" semantics explicit. Cleanup verified by
`tc qdisc show`.

**Tests (new `tests/test_fault_proxy_privileged.py` — skips without
`CAP_NET_ADMIN`, mirroring existing capability-gated suites).**
- success: `--netem` on a **veth** injects measurable loss a raw ping/UDP probe
  sees below TCP.
- error (**fail-closed**): `--netem` without `CAP_NET_ADMIN` exits non-zero with a
  clear message and installs **no** qdisc (`tc qdisc show` clean).
- security-neg (**cleanup**): after SIGKILL then `--cleanup <tag>`, `tc qdisc show`
  shows zero residual tagged qdisc.

---

### R2 · Transparent interception — M

**Problem.** Today the client must be pointed at the proxy. Real on-path elements
intercept unmodified clients.

**Surface.** `--transparent [--redirect-ports LIST]` installs a tagged
`nftables`/`iptables` `REDIRECT` (or `TPROXY` + `IP_TRANSPARENT`) so existing
connections are transparently relayed; the original destination is recovered via
`getsockopt(SOL_IP, SO_ORIGINAL_DST)` and used as the upstream (no `--target`
needed).

**Mechanism.**
```
# REDIRECT model (simplest):
iptables -t nat -A OUTPUT -p tcp --dport <D> -j REDIRECT --to-ports <listen>  # tagged via comment
# then per accepted socket: getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, …) -> dial that
```
Rules tagged (iptables `-m comment --comment brixfp-<tag>` / nft named chain) for
scoped teardown.

**Compat/edge.** `SO_ORIGINAL_DST` replaces `dial_any` when transparent; the
target pool is optional (override). Loopback control gate still enforced.

**Tests (`test_fault_proxy_privileged.py`).**
- success: a client connecting to an origin it was **never told** to proxy is
  intercepted (a fault injected on that flow is observed).
- error (fail-closed): no `CAP_NET_ADMIN` → refuse, install no rule.
- security-neg (cleanup): SIGKILL + `--cleanup` → `iptables -t nat -S` /
  `nft list ruleset` show zero residual tagged rules.

---

### R3 · Namespace topology / partitions — L

**Problem.** The single relay cannot express multi-node split-brain (Blockade's
domain).

**Surface.** `--partition SPEC` reads a tiny topology file (nodes → veth/netns →
reachability groups) and can partition endpoints into islands, then heal them via
the control port (`partition <groupA> <groupB>` / `heal`).

**Mechanism.** `ip netns add`, `ip link add veth… type veth peer…`,
`ip link set … netns …`, address assignment, and drop rules between islands;
teardown deletes all tagged netns/veth. Requires root/`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`.

**Compat/edge.** Heaviest item; v1 supports two islands + heal, not arbitrary
meshes. Cleanup enumerates tagged `ip netns list`.

**Tests (`test_fault_proxy_privileged.py`).**
- success: two endpoints in separate netns lose/gain reachability on
  `partition`/`heal`.
- error (fail-closed): insufficient caps → refuse, create no netns.
- security-neg (cleanup): SIGKILL + `--cleanup` → `ip netns list` shows zero
  residual tagged namespaces.

---

### R4 · Optional TLS termination — L — *stretch / evaluate*

**Problem.** On a TLS stream every byte lever except sever/delay is neutralised —
`corrupt` just trips the record MAC and never reaches the application. To fault
*inside* an encrypted `roots://`/`https://` session you must terminate TLS.

**Surface.** `--tls-intercept --ca <cert+key>` (explicit, operator-trusted CA;
**required**, no auto-generation into a default trust store). Terminates TLS, runs
the **existing byte levers** on the plaintext, re-encrypts upstream. **No HTTP
parsing** — this is "let the byte levers reach inside TLS," not a mitmproxy clone.
Prints a loud security banner; refused unless explicitly enabled.

**Mechanism.** A TLS front (OpenSSL, already linked in the wider tree) mints a
leaf per SNI from the provided CA; the plaintext is spliced through the unchanged
`forward_faulted` engine. Lives entirely in a new opt-in TU so I2 holds (the core
never sees TLS).

**Compat/edge.** This is the **only** feature touching the protocol-agnostic
invariant; therefore **evaluate-not-commit** — build only on real demand.
Off by default; explicit CA; targeted rewriting (find/replace on plaintext) is a
possible sub-feature but stays behind the same gate and is *not* in v1.

**Tests (`test_fault_proxy_privileged.py`, TLS-guarded).**
- success: with a trusted test CA, `corrupt` on the plaintext is observed by the
  application inside the TLS session (impossible without termination).
- error: missing/invalid `--ca` → refuse to start (no self-signed fallback).
- security-neg: without `--tls-intercept`, TLS bytes pass through opaque and
  `corrupt` only trips the MAC (proves the default never terminates TLS).

---

### R5 · Kernel EDT pacing — S — *bridge item, likely promote to B5*

`SO_MAX_PACING_RATE` yields a smoother bandwidth ceiling than `usleep`. It works
**unprivileged** for modest rates, so evaluate folding it into B5 (Track U) rather
than gating on root; kept here only as the kernel-pacing counterpart to note.
Tests ride B5's `TestRate`.

---

## 4. Consolidated test matrix

Every row is 3 tests (success · error · security-negative) per I6. Guarded rows
self-skip when the capability is absent so the **fast lane stays green**.

| Item | File | Class | Guard |
|------|------|-------|-------|
| A1 | `test_brix_fault_proxy.py` | `TestPersistentSession` | — |
| A2/A4 | `test_brix_fault_proxy.py` | `TestJsonControl` | — |
| A3 | `test_brix_fault_proxy.py` | `TestCtlClient` | — |
| B1 | `test_fault_proxy_fidelity.py` | `TestToxicity` | — |
| B2 | `test_fault_proxy_fidelity.py` | `TestSlowClose` | — |
| B3 | `test_fault_proxy_fidelity.py` | `TestConnectDelay` | — |
| B4 | `test_fault_proxy_fidelity.py` | `TestRefuse` | — |
| B5 | `test_fault_proxy_fidelity.py` | `TestRate` | — |
| B6 | `test_fault_proxy_fidelity.py` | `TestLatencyDist` | — |
| C1 | `test_fault_proxy_toxics.py` | `TestNamedToxics` | — |
| C2 | `test_fault_proxy_routes.py` | `TestDynamicRoutes` | — |
| D1 | `test_brix_fault_proxy.py` | `TestMetrics` | — |
| D2 | `test_brix_fault_proxy.py` | `TestEventLog` | — |
| R1 | `test_fault_proxy_privileged.py` | `TestNetem` | `CAP_NET_ADMIN` |
| R2 | `test_fault_proxy_privileged.py` | `TestTransparent` | `CAP_NET_ADMIN` |
| R3 | `test_fault_proxy_privileged.py` | `TestPartition` | `CAP_NET_ADMIN+SYS_ADMIN` |
| R4 | `test_fault_proxy_privileged.py` | `TestTlsIntercept` | root + OpenSSL |

**Harness conventions (match the existing suites).** Lifecycle via
`LifecycleHarness`/`NginxInstanceSpec` where an origin is needed; otherwise a tiny
stdlib TCP echo/sink server + `socket` client, exactly as
`test_fault_proxy_corruption.py` does today. Ports come **only** from the ledger
(§6) — no host literals (AST guard). Privileged tests probe caps with
`os.geteuid()` / a `tc`-dry-run and `pytest.skip` cleanly.

---

## 5. Build integration (three build systems)

New TUs introduced by this plan:
`brix_fault_proxy_json.c` (A2/A4, D1), `brix_fault_proxy_ctl.c` (A3),
`brix_fault_proxy_toxic.c` (C1), `brix_fault_proxy_route.c` (C2),
`brix_fault_proxy_netem.c` / `_transparent.c` / `_netns.c` / `_tls.c` (R1–R4).

For **each** new `.c`:
1. Add to the standalone **`FAULT_PROXY_SRCS`** list (the proxy links outside the
   ngx-free client tree — `[[phase38-client-splits-landed]]`).
2. Add to the repo-root **`./config`** source list (re-run `./configure
   --add-module=$REPO` only after source-list changes).
3. Add to **`client/Makefile`**.
4. Add to the **RPM spec** file list (`split_files_three_build_systems`).
5. Keep every file **<600 lines** (file-size guard) — split by plane as the
   existing four TUs already do; that is *why* each capability is its own TU.
6. `tools/ci/check_brix_namespace.py` — all new symbols `brix_`/`fp_`-prefixed.
7. Validate: `make -j$(nproc)` in `client/`, then run the new pytest files.
8. Update **`client/man/brix-fault-proxy.1`** (new verbs/flags) and the two site
   pages (`site/src/pages/network-testing.astro`, `interoperability.astro`) once a
   phase lands, adding an honest **"what it deliberately does not do"** note
   citing §9.

---

## 6. Port allocation

Reserve a contiguous block in `tests/fleet_lifecycle_ports.py` **after** the
`gridftp-xproto` entry (31194 + extra 31195). Ports 31196–31210 are currently
unallocated (highest live entry is 31195; next used is 31999).

| Ledger key | Port | Used by |
|------------|------|---------|
| `fault-proxy-session` | 31196 | A1 |
| `fault-proxy-json` | 31197 | A2/A4/D1 |
| `fault-proxy-ctl` | 31198 | A3 |
| `fault-proxy-fidelity` | 31199 | B1–B6 (listen) |
| `fault-proxy-fidelity-ctl` | 31200 | B1–B6 (control) |
| `fault-proxy-toxics` | 31201 | C1 |
| `fault-proxy-route-a` | 31202 | C2 primary |
| `fault-proxy-route-b` | 31203 | C2 dynamic route |
| `fault-proxy-metrics` | 31204 | D1 |
| `fault-proxy-eventlog` | 31205 | D2 |
| `fault-proxy-priv` | 31206 | R1–R4 (guarded) |
| *(reserve)* | 31207–31210 | headroom |

Add each as a normal `{"port": N}` ledger entry (control ports either as a second
key or via an `"extra"` map like `gridftp-xproto`'s `DAV_PORT`). Confirm no
collision at add time (`grep -oE '3[12][0-9]{3}' tests/fleet_lifecycle_ports.py`).

---

## 7. Sequencing & acceptance gates

```
Track U (default):  A ──► B ──► C ──► D
Track R (opt-in):        R1 ──► R2 ──► R3 ──► (R4 evaluate)
                         R5 → fold into B5 if unprivileged
```

- **Milestone U1 (A+B):** small, hot-path-safe; closes most Toxiproxy
  usability/fidelity gaps. **Gate:** all A/B classes green; `status` regression
  test proves no wire break (I5).
- **Milestone U2 (C):** the architectural lift. **Gate:** flat fast-path
  throughput within tolerance of a pre-C1 baseline (risk-8 below); routes bind via
  the unchanged gate (I4).
- **Milestone U3 (D):** rides C's per-route counters. **Gate:** `/metrics` gate
  test + no-payload-in-log test green.
- **Track R** can begin in parallel after A (reuses the grammar). **Gate for every
  R item:** the fail-closed test and the cleanup test are both green, and the
  fast lane is unaffected (guarded skips).

Each phase is independently shippable and revertible; nothing breaks the existing
grammar (I5).

---

## 8. Risk register

| # | Risk | Mitigation |
|---|------|-----------|
| R-1 | Named-toxic list walk (C1) regresses the hot path | Snapshot list once per read (mirror `relay.c:240`); keep the flat fast-path when `g_ntoxics==0`; throughput micro-assert vs baseline. |
| R-2 | Root-mode kernel state leaks on crash | Tagged rules/qdiscs/netns + atexit/signal revert + `--cleanup <tag>`; a security-neg cleanup test per R item asserts zero residual after SIGKILL. |
| R-3 | TLS-intercept (R4) erodes I2 | Off by default, explicit-CA-only, no HTTP parsing, loud banner, separate opt-in TU; evaluate-not-commit. |
| R-4 | Control-plane surface growth → auth pressure | Hold loopback-default + `--insecure-bind` for **every** new surface (JSON, `/metrics`, routes); revisit real auth only on a genuine remote use case. |
| R-5 | Fast lane slowed / flaked by privileged tests | Track R tests self-skip without caps; timing asserts use tolerances + monotonic clock (WSL2 clock-step, `[[wsl2-clock-backwards-steps]]`). |
| R-6 | JSON parser (A2) is a hand-rolled scanner → parsing bugs | Keep it a thin front-end that reprojects to the one verb grammar (no duplicate lever logic); fuzz-style malformed-input test; it only ever runs on the loopback control port. |
| R-7 | Struct/ABI churn (`lever_t`, `relay_arg` grow) across TUs | Clean rebuild after header changes (`struct_field_abi_clean_rebuild`); additive fields only; bump nothing that the existing tests snapshot. |

---

## 9. Rejected features (non-goals, with rationale)

From mitmproxy/Burp/ZAP (L7). **Out of scope by design** — building them would
dilute a sharp tool into a weak clone of a mature one:

- **HTTP/WS/HTTP2/HTTP3/gRPC message parsing.** That is a protocol suite; our
  value is being protocol-blind (I2).
- **Repeater / Intruder / fuzzing / active vuln scanning.** Application-security
  workflow; use Burp/ZAP.
- **Flow capture / HAR export / searchable history.** D2 logs *fault events*, never
  payload bytes — capture stays out (a D2 security-neg test enforces this).
- **GUI/TUI, per-flow addon scripting.** mitmproxy's domain.
- **Targeted find/replace rewriting on parsed fields.** The core mutates *random*
  bytes on purpose (models a flaky NIC / on-path bit-flipper an application
  checksum must catch). Field-targeted rewriting only makes sense after TLS
  termination and stays behind the R4 gate, not a default.

The **only** L7-adjacent capability adopted is optional **TLS termination** (R4),
solely to let the existing byte levers reach *inside* an encrypted session —
nothing more. The tool remains a **root-free, protocol-agnostic
transport-integrity fault injector.**
```
