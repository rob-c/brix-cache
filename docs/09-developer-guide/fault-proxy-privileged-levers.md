# brix-fault-proxy Privileged (Root) Levers and the MITM/Attack/Protocol Expansion

## Context

`brix-fault-proxy` is a standalone, root-free TCP fault-injection proxy
("toxiproxy-lite") shipped with the client tooling. It corrupts, delays, and
mangles traffic entirely in userland, above the TCP layer. That is enough for
most chaos tests, but it cannot reproduce the failures that live *below* TCP:
packet loss and reordering imposed by the NIC, kernel-crafted RST/ICMP verdicts,
or a next-hop MTU black hole. Those effects are exactly what the planned
root-ful "bad-network" client/server resilience tests need.

To cover them, a **root-gated privileged subsystem** was added (2026-07-23),
followed by several **root-free** expansions (MITM/DoS, attack-mocking, protocol
surgery + session replay + an exec oracle). This record captures the design,
the gating, the file layout, and the netns root-test pattern.

## What changed / decision

### 1. Privileged ("priv") below-TCP levers — root-gated

New module `client/apps/diag/brix_fault_priv.{c,h}` (~723 LOC), wired into the
core `client/apps/diag/brix_fault_proxy.c`:

- Control-port dispatch for the `priv` command family.
- `--privileged` and `--priv-iface IFACE` flags (`fp_config.privileged`,
  `fp_config.priv_iface`).
- `fp_arm_privileged()` in `brix_fault_proxy.c` arms the subsystem and installs
  SIGINT/SIGTERM/atexit teardown so an interrupted run never leaves the NIC
  impaired (`fp_priv_teardown()` uses only fork/execvp/waitpid).

Levers (control-port commands, prefix `priv`):

- **`netem delay|loss|loss-gemodel|corrupt|duplicate|reorder|rate|limit|clear|show`**
  — real `tc qdisc … netem` on the `--priv-iface` egress. A per-feature fragment
  table (`g_ne[NE_N]`) is kept and the whole qdisc is re-emitted on each change
  by `netem_apply()`; `delay` is emitted before `reorder` so `tc netem` honours
  the hold-back.
- **`cut <rst|drop|icmp-admin|icmp-host|icmp-net|icmp-port> [up|down]`** + **`uncut`**
  — kernel-crafted verdicts via an `nft` table `inet brix_fault_proxy` with an
  input hook, scoped to the listen/target ports. The ruleset is piped to
  `nft -f -` over a pipe.
- **`mtu <bytes>|restore`** — shrinks the NIC MTU (via `/sys/class/net/<iface>/mtu`,
  original saved in `g_mtu_saved`) to wedge large transfers behind a next-hop MTU
  black hole / forced fragmentation — a below-TCP effect no userland relay can fake.
- **`clear`**, **`status`**.

Man page: new `.SH PRIVILEGED (ROOT) LEVERS` section in
`client/man/brix-fault-proxy.1`.

Tests: `tests/test_fault_proxy_privileged.py`.

The Makefile target `$(BINDIR)/brix-fault-proxy` (`client/Makefile`, `FAULT_PROXY_SRCS`)
compiles all fault-proxy `.c` files, including `brix_fault_priv.c`.

### 2. Root-free MITM/DoS expansion

New module `client/apps/diag/brix_fault_ext.{c,h}` (pure/unit-testable) plus relay
glue in `brix_fault_proxy.c`. Tests: `tests/test_fault_proxy_mitm.py`. Levers
(CLI `--flag` + control commands, per-direction where noted): `replace <F> <R>`
(wire rewrite), `inject <payload>` (one-shot splice; `hex:`/`str:` with
`\r \n \xNN` escapes), `drop-bytes`/`repeat-bytes` (framing desync/inflation),
`delay-first`, `mss`/`rcvbuf`/`sndbuf` (TCP_MAXSEG / SO_* squeeze),
`stall`/`unstall` (backpressure without sever), `max-lifetime` (time-boxed conn),
`proxy-header v1|v2 SRC [DST]` (forged PROXY-protocol source-IP spoof),
`chaos <ms>` (autonomous seed-deterministic random-lever monkey). `status` gained
a 2nd "ext …" line with counters (dropped/repeated/injected/replaced); `clear`
resets all. Man page: `.SH EXTENDED MITM AND DOS LEVERS`.

### 3. Attack-mocking toolkit

All in `brix_fault_proxy.c`; tests `tests/test_fault_proxy_attack.py`. Composes the
primitives into "topple a target service" behaviours, still root-free, control-port
+ `--flag` driven (routed via `cmd_set_attack` in the `apply_command` chain):
`trigger[-once] <dir> <pat> <cmd>|off` (content oracle — memmem scan, fires a
control CMD through `apply_command`), `mangle-len <dir> <off> set|add|sub <v>`
(forge a BE32 length field), `accept-pause <ms>` (accept-queue pressure in
`fp_accept_loop`), `fanout <N>` (open N extra held upstreams, cap 16 —
pool/fd exhaustion), `global-rate <kbps>` (one shared token bucket across all
conns, `global_rate_gate` before write in `forward_segment`), `flap <up> <down>|off`
(flap thread cycles block/unblock), `ramp <lever> <start> <end> <ms>` (20-step
linear sweep of any numeric lever). `preset <name>|list` expands named realism +
attack profiles (satellite / hotel-wifi / 3g-lossy / … / slowloris / slowread /
rst-flood / truncate-bomb / …). `status` gained a 3rd "attack …" line; `status json`
one-line snapshot for harnesses. Man page: `.SH ATTACK-MOCKING LEVERS`.

### 4. Protocol surgery + session replay + exec oracle

New modules `brix_fault_tls.{c,h}`, `brix_fault_http.{c,h}`,
`brix_fault_replay.{c,h}`, `brix_fault_oracle.{c,h}` + shared `brix_fault_buf.h`;
relay glue in `brix_fault_proxy.c`. Tests: `tests/test_fault_proxy_protocol.py`.
TLS/HTTP are pure functions over caller buffers; the relay chains TLS→HTTP→ext via
ping-pong scratch buffers so no stage overwrites its input.

- **`tls` (`--tls`):** `set-type`, `fragment`, `set-version`, `inflate`,
  `drop-type`, `flip` (MAC break), `alert`, `off`. Walks 5-byte record headers.
  `fp_tls_cfg_init()` installs `-1` sentinels (zero-init would read `set-type=0`
  as active), called before `parse_args` and in `clear`.
- **Phase-99 DPI/middlebox pathology levers (root-free)** — reproduce the
  "works in Chrome, kills XRootD/GridFTP/FTS" failures of an overloaded/mis-
  configured cloud DPI (`docs/refactor/phase-99-dpi-middlebox-pathology-levers.md`;
  dispatch in `brix_fault_cmd_dpi.c`, relay glue in `brix_fault_pump.c`, accept-loop
  glue in `brix_fault_proxy.c`): **`idle-reap <ms> [black-hole|rst]`** (conntrack
  idle eviction — silent freeze or forged RST), **`eat-100-continue`** (swallow a
  100 interim so an `Expect: 100-continue` upload hangs), **`rst-after <ms>`** /
  **`max-bytes <n> [rst|fin]`** (classify-and-kill guillotines, folded into
  `pump_severed`/the byte total), **`drop-fin [up|down]`** (asymmetric teardown via
  per-direction EOF suppression in `relay_pump`), **`classify-throttle <bytes>
  <kbps>`** (volume slow-lane paced in the pump), **`hello-split-reset <thresh>`**
  (RST an oversized TLS ClientHello read from the record header — split-safe),
  **`syn-drop <ppm>`** (silent accept drop), **`alg-rewrite <src> <dst>`** (FTP
  PASV endpoint rewrite over the `replace` mutation buffers). Counters: `reaped
  ate_100 fin_dropped throttled hello_reset classify_kills syn_dropped`; status
  gained a `dpi …` line. All reset by `clear_all`. Below-TCP siblings live under
  `--privileged`: **`priv frag-drop`** (drop IP fragments), **`priv
  first-not-syn-drop`** (`ct state invalid` drop), **`priv strip-opt`** (degrades
  with a clear reason — needs NFQUEUE/eBPF). A root-free **UDP relay** (`--udp
  "<listen> <host:port>"`, `brix_fault_udp.c`) carries the "UDP vs TCP" class:
  `udp-drop <ppm>`, `udp-hold-until-tcp <ms>`, `udp-reap <ms>`, `udp-reorder
  <ppm> <ms>`. Tests: `tests/test_fault_proxy_dpi.py`,
  `tests/test_fault_proxy_udp.py`, and the Wave-B cases in
  `tests/test_fault_proxy_privileged.py`.
- **`http` (`--http`):** `cl-te`/`te-cl` (request-smuggling desync), `dup-cl`,
  `obfuscate-te 1|2|3`, `naked-lf`, `inject-header`, `append`, `off`. All-zero
  cfg is inert. **`header-hold <thresh> <ms> [partial|whole]`** replicates the DPI
  middlebox anti-feature that stalls an HTTP(S) request once its *header block*
  reaches `<thresh>` bytes (e.g. a fat client-cert PEM in an XrdHttp request
  header): `whole` (default) delays the whole segment by `<ms>`, `partial`
  releases the first `<thresh>` bytes then holds the remainder. Unlike the
  smuggling levers this is a *timing* effect applied in the relay pump
  (`fp_http_hold_decide()` in `brix_fault_pump.c`), not a buffer rewrite, so it is
  deliberately **excluded from `fp_http_active()`**; it fires only on a complete,
  over-threshold header block (`CRLFCRLF` present) so a body-only segment is never
  held. Counter `held`; status shows `hold=<up>/<down>`. Tests:
  `tests/test_fault_proxy_header_hold.py`. Phase-99 added the store-and-forward
  sibling **`http body-hold <thresh> <ms> [partial|whole]`** (stalls on body size —
  bytes after the terminator) and **`http strip-header <name>`** (drops a header
  line, e.g. `Range` → full-object read); both also live in `fp_http_cfg`,
  `body-hold` excluded from `fp_http_active()` like `header-hold`.
- **`record <path>|off` / `replay <path>|off` / `replay dir up|down`:** framed
  capture (magic `BFPR\1`, `[dir:1][ts_ms:8BE][len:4BE][bytes]`); replay is a
  synthetic peer with no upstream dial.
- **`bisect <lever> <lo> <hi> <timeout_ms> <cmd>`** (space-separated) /
  **`recovery <fault>|<hold_ms>|<probe>|<timeout>`** (PIPE-separated). The oracle
  (`brix_fault_oracle.c`) runs `fork` + `setsid` + `close_range(3, ~0U, 0)` +
  `execl /bin/sh -c`, `waitpid` 10 ms-poll, SIGKILL group on timeout. Poll results
  via `bisect-result` / `recovery-result`. `bisect` assumes monotonic severity.
  Both are **double-gated on `--enable-exec`** (analogous to `--privileged`).
  Man page: `.SH ORACLE-DRIVEN LEVERS`.

## Why

- **Gating.** The privileged subsystem arms only when **euid == 0 AND `--privileged`**
  are both present (`geteuid() != 0` is refused in `brix_fault_priv.c`; root alone
  will not arm it, and `--priv-iface` without `--privileged` is an error). The
  exec oracle is analogously double-gated on `--enable-exec`. Fault injection that
  touches host kernel state or spawns processes must be opt-in and explicit.
- **No shell.** Every external command is `fork()` + `execvp()` with an explicit
  argv (never a shell string); interface names are validated against a charset and
  must exist under `/sys/class/net`, so a bad `--priv-iface` fails loudly. The
  control parser never invokes a shell — a security test proves a `$(...)` payload
  is treated as a literal, not executed.
- **Auto-restore.** All host state (netem qdisc, nft table, MTU) is torn down on
  any exit path (signal / atexit), so an aborted run cannot leave the NIC impaired.
- **Deliberate non-goal.** Raw spoofed-source ICMP "fragmentation needed" was
  intentionally **not** shipped: RFC 5927 sequence validation makes off-path
  forgery unreliable, and `priv mtu` produces the same wedged-transfer outcome
  deterministically.

## Testing

### netns root-test pattern (reuse for root-ful bad-network tests)

`tests/test_fault_proxy_privileged.py` establishes the pattern for the root-ful
bad-network suite:

- **Isolation:** everything runs inside an `ip netns` operating on that namespace's
  isolated `lo`. Real host NICs are never touched, and a leaked qdisc / nft table /
  MTU change dies with the namespace. The `netns` fixture does
  `ip netns add`/`del` and reaps `ip netns pids` on teardown.
- **Reaching the in-ns proxy:** the proxy is launched with `ip netns exec NS <bfp> …`;
  control commands reach the in-ns control port via
  `ip netns exec NS python3 -c …` (`_ctl` / `_nsrun` / `_run_in_ns` helpers).
- **Skips:** `needs_root = pytest.mark.skipif(...)` skips off-root or when
  iproute2/nftables are unavailable. The netem sub-tests additionally skip when the
  kernel lacks `sch_netem` (`_netem_supported`). This dev box's elrepo 6.15 kernel
  lacks `sch_netem`, so the netem test is 1 expected skip; the nft/mtu/teardown
  tests run everywhere root is available.
- **Coverage:** installs-and-tears-down (netem), cut + mtu install/restore, and
  teardown-restores-nft-and-mtu on signal.

### Root-free tests

`tests/test_fault_proxy_mitm.py`, `tests/test_fault_proxy_attack.py`, and
`tests/test_fault_proxy_protocol.py` cover the userland levers without root.

Run: `PYTHONPATH=tests pytest tests/test_fault_proxy_privileged.py -v` (and the
other `test_fault_proxy_*.py` files).

## Build / guard gotchas

- `tools/ci/check_duplication.py` scans `client/` (`TREES = ("src", "client", "shared")`),
  not just `src/`, and tokenizes identifiers, so near-identical function prologues
  trip it — extract a helper (done for `parse_pair` / `fp_hostpair` in
  `brix_fault_ext.c`). The file-size guard is `src/`-only.
- In the oracle's forked child, do **not** loop `close()` up to `RLIMIT_NOFILE`
  (`ulimit -n` here is 524288 → ~500k syscalls/fork); use `close_range()` (one
  syscall, kernel ≥ 6.15).
- A recovery/bisect "relay wedge" during test bring-up was a **test-harness bug**,
  not the proxy: the harness echo server did `except OSError: break` in its accept
  loop, killing accept on any transient error and mimicking a proxy hang. Fix:
  `except OSError: continue`.
- Mutation scratch in `relay_pump` is a plain stack buffer (not `_Thread_local` —
  avoids TLS zero-init latency).
