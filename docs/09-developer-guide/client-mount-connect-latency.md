# Client mount & connect latency

**Status:** implemented 2026-06-27 · **Scope:** `xrootdfs` FUSE mount, `xrdfs`
(and every native CLI tool) connect path · **Related:**
[fuse-async-resilient-driver.md](fuse-async-resilient-driver.md),
[lifecycle-startup-shutdown-performance.md](lifecycle-startup-shutdown-performance.md)
(the server-side analog), [coding-standards.md](coding-standards.md)

This is the engineering writeup of a measure-first pass over how fast the native
client tools *start talking to a server*: the methodology, what the numbers
actually said (which was not what the brief assumed), the changes that followed,
and several pre-existing issues the investigation surfaced.

The brief was: *"make the speed of mounting `xrootdfs` and `xrdfs` as close to
0ms as possible."*

---

## 1. The method: measure before touching anything

The instinct on a "make it faster" brief is to start trimming suspects — shrink
the binary, drop shared libraries, cache things. That instinct is usually wrong,
and it was wrong here. The first move was to get honest numbers for **where the
time actually goes**, and let the data pick the target.

Everything below was measured with `strace -tt -T` (timestamped syscalls with
per-call duration), `strace -c` (syscall time histogram), `LD_DEBUG=statistics`
(dynamic-loader cost), and a `perf_counter` Python harness for sub-millisecond
wall-clock medians over many runs. All numbers are localhost (loopback RTT ≈ 0),
so they isolate **fixed per-invocation cost** from network round-trips. On a real
remote link you add the RTTs back — which, as it turns out, is the whole story.

---

## 2. What the numbers said

### 2.1 `xrdfs` (the CLI) is already near the floor

A full `xrdfs ls /` against a localhost anon server: **~3 ms wall, median.**
Decomposed:

| Cost | Measured | Notes |
|---|---|---|
| Process exec + dynamic linker | ~140 µs | `LD_DEBUG=statistics`: 421 k cycles total, 24 shared libs |
| `mmap` of shared libs | ~half of syscall time | 107 `mmap`s — but cheap in absolute terms |
| First `getaddrinfo` | the biggest *avoidable* chunk | triggers a one-time lazy `dlopen` of the glibc NSS modules (`libnss_files`/`libnss_dns`/`libresolv`) |
| Second NSS lookup | small | `getpwuid()` for the login username |
| Handshake → login → protocol → op | small on localhost | well-pipelined already; this is real RTT on a remote link |

The surprising result: the 24 shared libraries (OpenSSL, krb5, five compression
codecs, liburing, …) cost only ~140 µs at startup. Static linking or
`dlopen`-on-demand would have been a large, risky change for sub-millisecond
gain. **The shared-lib count is a non-problem.** The only genuinely avoidable
per-invocation costs are the two NSS lookups, and they are small.

The trap to avoid: under `strace` everything is ~5× slower, so the *absolute*
strace timings (e.g. a "12 ms" gap loading NSS modules) are inflated. Use strace
for the **relative sequence and call counts**, and the unstraced `perf_counter`
harness for true wall time.

### 2.2 `xrootdfs` (the mount) is where the latency lives

The mount command opened **five TCP connections, each with a full
handshake + login + auth, serially, before `mount` returned:**

| Step | Code | Cost |
|---|---|---|
| `xrdc_pool_create` (metadata pool) | `lib/pool.c` — connects slot 0 eagerly, rest lazy | 1 × connect+handshake+auth |
| `xrdc_mgr_create(streams=4)` (data streams) | `lib/aio_mgr.c` — a **serial** `for` loop | 4 × connect+handshake+auth |
| `xrdc_ext_probe` (vendor POSIX-ext probe) | `apps/xrootdfs.c` — `kXR_Qconfig` | +1 round-trip |

On localhost (~3 ms/connection) that is ~15 ms — invisible. **On a real remote
server with 30 ms RTT and GSI auth (multi-round + crypto per connection), each
connection is 100–300 ms, so the mount blocks for 0.5–1.5 seconds.** That is the
"mounting is slow" the brief was about, and it was entirely hidden by testing on
loopback. The lesson: *measure on the topology where the pain is reported.* When
that is not available, reason explicitly in units of `connections × RTT`.

The key structural insight: **only one connection needs to be live before
`mount` returns** — enough to fail fast on a bad endpoint or bad credentials.
The other four data streams and the extra pool slots are only needed on the
first file *read/write*. They were being paid for, serially, at mount time for
no benefit.

---

## 3. The changes

Two independent levers fell out of the measurement: **parallelize** the
connections that must happen at mount, and **defer** the ones that don't.

```text
  each [conn] = connect + (TLS) + login + auth  ≈ 1 RTT (100–300 ms on a real link)

  BEFORE  serial eager (5 conns before mount returns)
   pool[conn] mgr[conn][conn][conn][conn] probe ──▶ mount   ≈ 5–6 × RTT
   ├────────┼────────┼────────┼────────┼────────┼─────▶

  DEFAULT  parallel eager — all live at mount, overlapped
   pool[conn]                                   ──▶ mount   ≈ 1 × RTT
   mgr [conn]   ┐ all four connect concurrently           (fail-fast + warm
   mgr [conn]   │ joined before the libfuse fork           before first I/O)
   mgr [conn]   │
   mgr [conn]   ┘
   ├────────────┴──▶

  --lazy-streams  one eager, rest on first read
   pool[conn] mgr[conn] ──▶ mount   ≈ 1 × RTT (lowest)
   ├────────┴────────▶          mgr[conn] ← connected lazily on first file read
                                under lazy_lock, double-checked, at-most-once
```



### 3.1 Parallel eager connect (default) — `lib/aio_mgr.c`

`xrdc_mgr_create` now connects its eager streams concurrently. Each
`xrdc_connect` (connect + optional TLS + login + auth) is independent, so they
overlap: mount-connect wall drops from `streams × RTT` to ~`1 × RTT`.

Mechanics that matter:

- The worker threads are **short-lived and fully joined before `mgr_create`
  returns.** This is critical: libfuse's default daemonization `fork()`s, and
  threads created before `fuse_main` do not survive into the child. Because the
  connect-threads are joined first, they never cross that fork. (The mount also
  runs `-f` in the test harness, so the long-lived async loop thread survives
  regardless — but the join discipline keeps the connect phase correct either
  way.)
- Attach-to-loop (`xrdc_aconn_attach`) is done **serially after** the parallel
  connects, because it touches the shared event loop and is not the slow part.
- A thread that fails to spawn runs its job inline, so the caller always sees
  every job's result.

### 3.2 Lazy streams (opt-in) — `--lazy-streams`

`xrdc_mgr_create` gained an `eager` parameter (clamped to `[1, nconns]`). Slots
beyond `eager` are left unconnected (`acs[i] == NULL`) and brought up on first
use inside `xrdc_mgr_pick`, under a `lazy_lock` with a double-checked test so
concurrent FUSE worker threads connect a given slot at most once. If a lazy
connect fails (a transient server hiccup), `pick` falls back to any already-live
stream — `eager ≥ 1` guarantees one exists, so `pick` never returns `NULL` and
the contract with callers is unchanged.

`xrootdfs --lazy-streams` connects exactly **one** stream at mount and defers the
rest, for the lowest possible mount latency, trading a one-time warm-up on the
first read. Default behavior is parallel-eager (all streams live at mount, but in
~1 RTT), preserving fail-fast and warm-before-first-I/O.

Verified directly by counting established connections immediately after mount,
before any I/O:

| Mode | Connections at mount | Expected |
|---|---|---|
| default, `streams=4` | 5 | pool 1 + mgr 4 |
| `--lazy-streams`, `streams=4` | 2 | pool 1 + mgr 1 |
| default, `streams=8` | 9 | pool 1 + mgr 8 |
| `--lazy-streams`, `streams=8` | 2 | pool 1 + mgr 1 |

### 3.3 Connect-path micro-wins (help `xrdfs` and the mount)

- **`getaddrinfo` hints** (`lib/sock.c`): `AI_NUMERICSERV | AI_ADDRCONFIG`. The
  port is always a decimal string, so `AI_NUMERICSERV` skips the `/etc/services`
  lookup. `AI_ADDRCONFIG` stops the resolver handing back a AAAA candidate on a
  host with no configured IPv6, which would otherwise burn a full failed connect
  attempt before falling back to IPv4. (The existing happy-eyeballs loop in
  `connect_resolved` still handles genuinely dual-stack hosts.)
- **Login username from environment** (`lib/conn.c`, `fill_username`): prefer
  `$LOGNAME`/`$USER` over `getpwuid(geteuid())`. The login username is the OS
  identity advertised for monitoring/default mapping — real authorization comes
  from the chosen security protocol — so the env fast-path is safe and skips an
  NSS lookup (which lazy-loads `libnss_*` on first call). Falls back to
  `getpwuid` when the environment is unset.

### 3.4 A concurrency prerequisite: localize the GSI rtag — `lib/sec/sec_gsi.c`

Parallelizing connects exposed a latent hazard. `gsi_first` used two
**file-static** variables (`g_client_rtag[8]`, `g_have_rtag`) for the round-1
random tag, with a comment explaining that "the CLI runs one connection at a
time, so a file-static is sufficient." The async manager is exactly the
multiplexing client that comment warned about — and parallel GSI handshakes would
race on that shared tag, corrupting each other's certreq.

The fix was clean because the tag turned out to be **written in `gsi_first` and
never read afterward** (`gsi_more` delegates verification to the shared
`gsi_core` kernel and ignores it). Its real lifetime is local to the one
function, so it became a stack local and `g_have_rtag` was deleted. For a single
connection this is byte-identical behavior; for concurrent connections it is the
correctness fix that makes §3.1 safe. (Audit note: the only other handshake-path
mutable globals are `sec_pwd.c`'s `g_pwd_pass_len` — exotic password auth — and
`cred_bearer.c`'s `g_tok`, which is set-once/read-mostly. Token, anon, unix, and
GSI parallelize safely.)

---

## 4. Validation

- Clean build (no warnings) across all client tools.
- `xrdfs ls` (anon, token) correct; median improved (~2.9 ms vs ~3.6 ms).
- Mount + `ls` + read correct in all four modes (default / `--lazy-streams` ×
  `streams=4` / `streams=8`).
- Lazy mode defers exactly `N−1` streams (connection-count table above) and a
  first read correctly forces a deferred stream to connect and returns the right
  bytes.
- Concurrent multi-stream reads (`--streams 6`, both modes) checksum-match the
  origin.
- GSI certreq is well-formed: against a server that doesn't trust the ad-hoc test
  proxy, the handshake reaches a `kXR_error` (4003) *authorization* reply — i.e.
  the server parsed and processed the request — rather than a malformed-request
  failure.
- `tests/test_xrootdfs.py`: **12 / 16 pass.** The 4 failures are a pre-existing,
  unrelated issue (§5.1).

**Not measured:** the parallel-vs-serial wall-clock win on a high-RTT link — the
test host had no passwordless `sudo` for `tc qdisc … netem delay`. The gain is
deterministic from `connections × RTT` and the connection-count mechanism is
proven directly. To get hard numbers:

```bash
sudo tc qdisc add dev lo root netem delay 20ms      # 40 ms RTT on loopback
# time the mount with and without --lazy-streams, streams=4 vs 8
sudo tc qdisc del dev lo root netem
```

---

## 5. Pre-existing issues surfaced (not caused by this work)

A measure-first pass tends to trip over unrelated breakage. Two are worth
recording so they aren't re-discovered cold.

### 5.1 `stat`-after-create returns ENOENT during write staging

The four failing `test_xrootdfs.py` cases are all **writes**, and all fail the
same way. The server log tells the story:

```
"OPEN /…/data/_f.bin wr"   OK     ← create succeeds; file exists on disk (0 bytes)
"STAT /_f.bin -"           ERR "No such file or directory"   ← but stat can't see it
"CLOSE /…/data/_f.bin -"   OK
```

The file *is* created, but a `kXR_stat` of its final path returns ENOENT until
`CLOSE` commits it — so FUSE's getattr-after-create concludes the create failed
and returns ENOENT to the application. This is **server-side write-staging
visibility** (the upload-resume `.part` path; see
[../refactor/](../refactor/) phase notes on `upload_resume` staging), not a
client bug. Proof it is pre-existing and independent of this work:

1. The `--legacy` FUSE driver (a completely separate I/O path that none of these
   changes touch) reproduces it identically.
2. A standalone `xrdfs stat` of the same file *after* the sequence succeeds.

Worth a separate look: a freshly `OPEN`ed file should be `stat`-able at its final
path (stock XRootD behaves this way, which is why FUSE-over-stock works).

### 5.2 Test-harness environment hazards

- **Expired test proxy.** `/tmp/x509up_u1000` expires daily; an expired proxy
  makes GSI ports reject with confusing errors. Regenerate:
  ```bash
  python3 utils/make_proxy.py /tmp/xrd-test/pki
  cp /tmp/xrd-test/pki/user/proxy_std.pem /tmp/x509up_u1000 && chmod 600 /tmp/x509up_u1000
  ```
  (See [resilience-PKI notes]; the resilience harness already auto-regenerates
  via `openssl -checkend`.)
- **Root-owned garbage temp dirs.** A prior impersonation/red-team run leaves
  root-owned files under
  `/tmp/xrd-test/tmp/pytest-of-rcurrie/garbage-*`, which blocks the conftest
  `start-all` session setup (and therefore the self-provisioning GSI suites).
  Clear with `sudo rm -rf /tmp/xrd-test/tmp/pytest-of-rcurrie/garbage-*`.

---

## 6. Takeaways

1. **Measure on the topology where the pain is.** Loopback hid a 0.5–1.5 s
   remote-mount cost behind a 15 ms localhost number. When the real topology
   isn't available, reason in `connections × RTT`, not in milliseconds observed.
2. **The cheap-looking suspects were cheap.** 24 shared libraries cost ~140 µs;
   chasing them would have been effort spent in the noise. The real cost was
   structural — *how many* serial round-trips the mount forced — not *how big*
   the binary was.
3. **Defer work that the critical path doesn't need.** Four of five mount-time
   connections existed only to be ready for a later read. Making them lazy (or at
   least parallel) is the entire win.
4. **Parallelism has prerequisites.** Concurrent connects were only safe once the
   GSI rtag stopped being a shared file-static. Audit handshake-path globals
   before fanning out.
5. **Keep the safety property.** One eager connection still validates the
   endpoint and credentials before `mount` returns, so "fail fast on a bad mount"
   survives both the parallel and the lazy mode.
