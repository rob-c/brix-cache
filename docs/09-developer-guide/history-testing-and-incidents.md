# Development History — Testing, Conformance, CI, and Production Incidents

**Date:** 2026-07-15
**Status:** Living historical record — synthesizes the test-harness evolution,
conformance-suite build-out, and production/load incidents from May–July 2026.
**Scope:** the pytest/xdist harness and its footguns, the differential
conformance program (stock-xrootd, WLCG x509, WLCG token, multiuser
permissions), chaos/reload/resilience testing, load/perf testing, the k8s test
lab, and postmortems for real bugs those efforts found. This is the incident
and decision record; canonical *how to run things* docs are
`tests/README.md`, `docs/09-developer-guide/testing-infrastructure.md`,
`docs/09-developer-guide/multiuser-conformance.md`,
`docs/09-developer-guide/wlcg-token-conformance.md`,
`docs/09-developer-guide/wlcg-ca-conformance.md`, and
`docs/10-reference/conformance/`. Don't re-derive those here; this doc says
what happened and why the guardrails exist.

**Related:** [lessons-migration-era-2026.md](lessons-migration-era-2026.md) ·
[postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md) ·
`docs/09-developer-guide/testing-infrastructure.md` ·
`docs/10-reference/xrootd-interoperability-conformance.md` ·
`docs/10-reference/conformance/` ·
`docs/refactor/phase-25-rate-limiting.md` ·
`docs/refactor/phase-29-phase3-aio-pipelining-spec.md` ·
`docs/refactor/phase-51-cross-protocol-resilience.md`

---

## Field guide — sharpest, most-likely-to-recur gotchas

Read this section before debugging a "mystery" test failure or a fleet that
won't come up. Each item cost real time at least once.

| Symptom | Real cause | Fix / rule |
|---|---|---|
| GSI/TLS tests fail "No protocols left to try" mid-suite, server logs `[emerg] hostcert.pem No such file` | Another process (`run_load_test.sh`, a peer session) wiped and regenerated `/tmp/xrd-test/pki` under the running fleet | Never run `run_load_test.sh` (or anything that regenerates PKI) concurrently against the shared fleet; isolate ports/PKI or serialize |
| A single test file run wedges/hangs the *next* manual `xrdcp`/TPC and looks like a server bug | `conftest.py` used to `stop-all` + `rmtree(TEST_ROOT)` on exit even when it only *attached* to an externally-started fleet | Fixed 2026-06-30: conftest only owns fleet lifecycle it started (`_external_fleet_attached()`); `TEST_OWN_FLEET=1` forces the old wipe behavior |
| Cache/staging tests fail with `EXDEV` or a node stops answering entirely | An orphaned `fuse.xrootdfs` mount from a crashed resilience test wedges any I/O that touches it forever | `mount \| grep fuse.xrootdfs`; `fusermount -u -z <mnt>`; then restart the wedged node (unmount alone does not un-wedge an in-flight worker) |
| Mass "regression" — dozens of files fail at collection with `TypeError` on `dict \| None` or `datetime.UTC` | `pytest` entry point on PATH resolves to Python 3.9 while `python3` is 3.13; 3.10+/3.11+ syntax fails at import, not at runtime | Check the pytest banner's Python version first; run via `python3 -m pytest` or repair the entry point before hunting a "regression" |
| `--dist loadgroup`/`loadscope` run aborts the *entire* session with `INTERNALERROR KeyError` after one worker crash | loadscope's `_assign_work_unit` can't replace a dead worker | Only `--dist load` (default) tolerates worker death; reserve loadgroup/scope for nothing broad — only the 11 `serial`-marked destructive suites need isolation, run those in a separate serial lane |
| Relative `tests/` path or a saved nodeid list yields "12 workers [0 items]" | `conftest._chdir_scratch()` chdirs every xdist worker into a scratch dir before collection; a relative arg resolves to nothing | Always pass absolute test paths / nodeids under xdist |
| `pkill -f pytest` / `pkill -f run_suite` / `pkill -f nginx` kills your own shell (exit 144) | These patterns self-match the invoking shell/wrapper | Use exact-comm `pkill -9 -x nginx`/`-x xrootd`, or `pgrep ... \| grep -v $$`; use `brutal_teardown.sh` as the canonical reaper (scans `/proc/*/cmdline` for test-path markers, skips `$$`/`$PPID`) |
| A resilience/fault-proxy or destructive test flakes when run inside the shared fleet | The shared fleet (11094-12126) is itself flaky to bring up and shares state with everything else | Resilience/fault-proxy/destructive suites must self-provision dedicated nginx+xrootd on a private high port block, own PKI/data dir — never call `start-all` for them |
| Every token **accept**-case fails while every **reject**-case passes (e.g. `test_wr_01/02/04_*_accept` red on webdav *and* s3, `test_wr_03_read_scope_denies_write` and all `*_reject` green) | Fleet **signing-key desync**, never a scope/authz code bug: `TokenForge` is minting with keys the servers no longer trust, so *all* tokens die at authN — reject-expecting tests then pass trivially. An interrupted `restart` (it boots ~76 servers and regenerates PKI, easily >2 min) leaves the dedicated instances (`/tmp/xrd-test/dedicated/webdav-token`, `s3-bearer`, …) holding stale keys, and can abort mid-PKI-regen so the main nginx `[emerg]`s on a missing `ca.key`/`hostcert.pem` | Do not chase it into `scopes.c`/`validate.c`. Re-run `restart` to completion in the background with a long timeout — it may need two passes (first wipes and regenerates PKI, second converges) — and confirm `/tmp/xrd-test/pki/{ca/ca.key,server/hostcert.pem,user/proxy.pem}` all exist before re-testing |
| A CI lane that boots the fleet reports **success** in seconds, having tested nothing (`asan: SKIP — sanitized fleet failed to boot on this runner`) | `start-all` aborted because a spec tagged `critical` **skipped** — `ref-anon` calls `pytest.skip("selected xrootd binary is unavailable: xrootd")` and no GitHub runner image ships stock XRootD. The launcher treated "not installed here" the same as "broken", and the lane script treats a boot failure as a missing prerequisite, so the two combined into a green check | Fixed 2026-08-09 (`_absorb_or_reraise`): `critical` is fatal on a real FAILURE only; a `pytest.skip` from any spec is absorbed and logged. When a lane's log says SKIP, read it as RED — no lane that skips its fleet is evidence of anything |
| A conformance/harness test "fails" and it looks like a server bug | Historically, ~90% of the time the *test* carried a stale assumption, not the server | Always verify differentially against a real stock `xrootd`/`XrdCl` reference before touching `src/`; see the conformance section below |
| Test failures/timeouts/high load and you're about to write "environmental, not code" | **BANNED.** This exact excuse buried a real crash-loop bug (uninitialized reaper timer, fixed `66efecd0`) for weeks — see the postmortem below | Check `coredumpctl list --since=-1h`, worker PID churn, and error.log for repeated startup banners BEFORE attributing anything to load |

---

## 1. The harness's shape and how it got fast enough to use

### 1.1 Fleet lifecycle and the conftest teardown footgun

In local mode, `tests/conftest.py` owns the shared fleet's lifecycle: at
session start it used to unconditionally wipe `TEST_ROOT` (`/tmp/xrd-test`)
and run `manage_test_servers.sh start-all`, and at session end always ran
`stop-all` + `rmtree(TEST_ROOT)`. The failure mode: running even a single test
file against a fleet someone had started manually would tear that fleet down
on exit, orphaning every still-running server's export-root file descriptors —
the next manual `xrdcp`/TPC attempt would hang, looking exactly like a
server-side TPC bug. This *was* the report that native TPC was "broken" on
2026-06-30; the TPC path itself was fine (6/6, byte-exact multi-chunk both
directions) — the bug was pure test-harness teardown.

Fixed the same day: conftest now manages the fleet lifecycle **only when it
started it**. `_external_fleet_attached()` probes the anonymous port at
session start; if something is already listening, conftest attaches (no
wipe/start-all/stop-all/rmtree) and prints a one-line notice.
`TEST_OWN_FLEET=1` forces the old clean-wipe-and-restart behavior for anyone
who wants it; `TEST_SKIP_SERVER_SETUP=1` still hard-skips lifecycle
management entirely (but also skips X.509 env setup — see §1.3).

### 1.2 start-all was slow, then wasn't

`manage_test_servers.sh start-all` brings up ~94 dedicated nginx instances,
~16 real xrootd reference daemons, and a 24-topology CMS mesh. Cold start
measured 104s. Three fixes, found by timestamped xtrace profiling
(`PS4='+ $EPOCHREALTIME ...'`), brought it to ~18s:

1. **TCP-first readiness probing.** `wait_ready_xrdfs` ran `xrdfs ls /`
   against every port on every poll; against a not-yet-listening port XrdCl
   burns its full 2s reconnect timeout before failing. Switched to a raw
   `/dev/tcp` connect probe at 50ms cadence, followed by exactly one `xrdfs`
   verification once the socket accepts. Saved ~22s.
2. **Backgrounding CMS mesh convergence.** `start_cms_mesh` (real CMS cluster
   convergence, previously run last and serial) now backgrounds immediately
   after PKI/token setup, with a `wait` barrier at the very end — it overlaps
   the ~14s dedicated-fleet startup instead of stacking after it.
3. **Concurrent mesh readiness polling.** `cms_mesh_lib.py:wait_ready` probed
   24 topologies serially; a not-yet-registered manager answers `locate` with
   `kXR_wait`, so each still-forming probe blocks up to its timeout and the
   round cost was the *sum* of every topology's stall. Switched to a
   `ThreadPoolExecutor` so the round cost is bounded by the slowest topology,
   with a short per-probe timeout (3s) and tight poll interval (0.3s). Stable
   ~8.7s across repeated runs, 24/24 topologies, full mesh interop suite
   green.

Deliberately **not** touched: cmsd's `cms.delay startup` (5s) is load-bearing
for cluster formation — lowering it to 2s was tried and is flaky (a data node
can miss the manager's initial registration window and then wait a full
re-register cycle). The ~8s multi-tier cmsd registration cascade is the real
floor.

### 1.3 The gotchas that live only in the harness, not the docs

These are non-obvious traps that cost real debugging time and aren't
self-evident from `tests/README.md`:

- **`TEST_SKIP_SERVER_SETUP=1` skips more than server startup** — it skips
  `conftest._setup_session()` entirely, including `X509_CERT_DIR`/
  `X509_USER_PROXY` env export. Anonymous tests pass, GSI tests fail "No
  protocols left to try" unless those vars are exported manually from
  `tests/settings.py`'s CA_DIR/PROXY_STD.
- **`start-all` returning exit 1 is not always fatal** — GSI/shared reference
  readiness probes can intermittently "fail" on pure timing even when the
  server is actually up; re-running once warm usually clears it. One
  systemic exit-1 cause was fixed: `start_all_dedicated` called
  `make_token.py gen` without first `init`-ing the tokens dir on a fully
  clean tree.
- **`critical` in a spec's tags means "a FAILURE here is fatal", not "this must
  exist".** Only two specs carry it: `main` (the shared nginx) and `ref-anon`
  (the stock reference xrootd). Until 2026-08-09 the launcher let *any*
  exception from a critical spec abort `start-all`, including the
  `pytest.skip("selected xrootd binary is unavailable: xrootd")` that
  `_start_xrootd` raises when the binary simply isn't installed — so on a host
  without stock XRootD (every GitHub runner) the whole fleet refused to boot,
  and the `asan` lane sailed through green having exercised nothing. The
  verdict now lives in one place, `_absorb_or_reraise`
  (`tests/_server_launcher_part2_mixina.py`), shared by the sequential and the
  threaded start path: a `pytest.skip.Exception` is "unavailable on this host"
  → log and continue, whatever the tags; anything else from a critical spec
  still propagates. `main` can't reach the skip branch (its start path raises
  `RegistryCommandFailure`), so an unbindable main nginx remains fatal.
  Guarded by `tests/test_fleet_criticality.py` — whose absorb cases convert a
  propagating skip into a `pytest.fail`, because otherwise the guard itself
  would go quietly *skipped*-green at the exact moment the bug returned.
- **Resource exhaustion from accumulated restarts.** Repeated `start-all`
  cycles leave orphans (seen: 44-79 nginx + 15 xrootd processes, host memory
  down to 100-500Mi free) until the OOM killer starts silently killing
  processes — `status` then reports "stopped" while 40+ nginx are actually
  alive. Use `manage_test_servers.sh start` (main + ref only, no dedicated
  fleet) when memory-constrained; it's sufficient for S3/WebDAV/stream
  functional tests.
- **`brutal_teardown.sh` is the canonical reaper** — `stop`/`stop-all` only
  reap pidfile-tracked instances. Self-provisioning test fixtures
  (conformance topologies, mirror, perf, hsproto, reference) leak
  pidfile-less orphans on fixed ports that block the next `start-all`.
  `brutal_teardown.sh` scans `/proc/*/cmdline` for test-path markers and
  reaps those, plus orphaned `krb5kdc`/`kadmind` and the `krb5/` realm dir.
  Do not hand-roll a `/proc` loop instead of using it.
- **Self-contained fixtures must bind ephemeral ports** (`settings.free_port()`
  / `free_ports(n)`), never port literals, or they collide with the always-up
  managed fleet. The #1 correctness bug in a multi-server topology fixture is
  forgetting to substitute a freed port into *every* cross-reference to that
  server (proxy_upstream, mirror_url, cluster member, client connect string).
- **xdist parallel-mode truth:** `--dist load` (default) tolerates a worker
  crash and redistributes; `loadscope`/`loadgroup` turn a worker crash into a
  session-aborting `INTERNALERROR`. Never use loadscope/loadgroup for a broad
  run — reserve serialization for the ~11 tests actually marked `serial`
  (`test_chaos_mesh`, `test_netfault_stream`, etc.), run those in their own
  serial lane instead.
- **`-n16` crashes workers on the shared fleet; `-n12` is the practical cap**
  measured on this hardware.
- A module-level `os.getcwd()` snapshot in conftest (`_ORIG_CWD`) could throw
  `FileNotFoundError` when a worker's scratch cwd was wiped mid-run by a
  concurrent test that `exec_module`s conftest for its own unit test —
  aborting the whole xdist run with "Different tests collected between gwN".
  Fixed with a `try/except OSError` fallback to repo root; this had been
  silently breaking full-suite runs.
- **Render nginx config templates with token substitution, never
  `str.format()`.** An nginx config is full of literal `{ }` blocks, so
  `.format()` raises `KeyError: ' '` on `events { }` before it ever reaches a
  placeholder. Use `.replace()`-style token substitution — and note the
  converse trap from the gsiftp client work: a template *comment* that names
  its own `{PLACEHOLDER}` gets substituted too.
- **The session-start wipe is not unconditional.** `conftest`'s
  `shutil.rmtree(TEST_ROOT, ignore_errors=True)` silently fails on a mode-`0555`
  directory holding `0444` files (a PKI fixture left one under
  `registry/xrdhttp/ca-public/`), leaving a *partially* wiped tree — worse than
  no wipe, because the survivors are stale. A fixture that chmods a directory
  read-only must restore the mode in teardown.
- **`TMPDIR` inside the fleet root may not exist.** It points at
  `/tmp/xrd-test/tmp`, so `tempfile.mktemp()` with no `dir=` hands back a path
  the client cannot create; with `xrdcp` that surfaces as rc 54, a *transport*
  failure, in every case including the clean control — a diagnosis that sends
  you looking at the wire.
- **Fixed test ports must sit below the ephemeral floor.** Anything ≥ 32768 can
  collide with an OS-assigned ephemeral port and is a latent bind flake, not a
  stable choice.
- **A suite that hardcodes ports instead of using the per-session tile
  allocator collides deterministically** with a second concurrent run or a
  leaked origin, and it presents as mass "mount failed" rather than as a port
  error. `PortBlock` tiles have their own trap: a fresh block allocated by a
  later test restarts at `base+10` and lands on the module fixture's live
  instances — stash the fixture's block and continue its sequence instead. And
  because `_CANON_HI` shifts whenever `PORT_BLOCKS` is edited under a running
  session, an edit can silently point a suite at a *foreign* origin.
- **Concurrent sessions clobber shared state mid-run.** A shared `/tmp` freeze
  directory or the shared build tree produces "unknown directive" reds that look
  like config regressions; rerun with a private `TEST_ROOT` and `NGINX_BIN`
  before believing them. Related: lint tests such as
  `test_no_new_direct_nginx_launches` trip on *other sessions'* untracked WIP
  files, so check `git status` provenance before claiming ownership of a lint
  failure. This class dominates: through the phase-97 CMS/CNS closure work,
  **every** red turned out to be a concurrent session's `TEST_ROOT` wipe or
  fixed-port contention and **none** was a code defect — so on a shared box the
  first move for any red is to re-run it alone in a private root, not to read the
  diff.
- **Some suites are only flaky under host saturation** (load 6–21 from other
  sessions) and pass 100% solo. Establish that before treating a rotating
  failure set as a product bug — but note that "the host is overloaded" is a
  banned *diagnosis* absent evidence (§4.1); the point here is to reproduce
  solo, not to hand-wave.
- **Assert robust properties, not fragile counts, against a live cluster.** A
  strict `count_frames(LOGIN) == base` flaked on a single incidental re-dial
  under an 8-minute serial run; a second LOGIN legitimately re-registers a
  second entry, so an aggregate `STATFS` doubles — assert "still alive and
  ≥ expected", not equality. Where a node may be mid-reconnect, wrap the send
  and assert survival.
- **`bytes([expr for i in ...])` is a list comprehension and raises
  `TypeError`** — use a generator: `bytes(expr for ...)`. Easy to miss when
  hand-building wire frames.
- **Wire-speaking stubs: three fixed traps.** (1) A stub manager's `stop()` must
  `shutdown(SHUT_RDWR)` its *accepted* connections, not just the listener —
  otherwise a lingering serve thread answers post-mortem locates and a failover
  test sees both ports alive. (2) The client-side session bootstrap order is
  handshake send → `kXR_protocol` send → **then** read both responses; reading
  between the two sends deadlocks. (3) The node sets `logged_in = 1` when the
  login frame is *sent*, not when the manager answers, so any stub that merely
  accepts TCP counts as a registered link — and conversely a **refused** dial
  surfaces on the read side, so count it in teardown, not at connect time.
- **A suite that skips on build failure hides the breakage.** Read the *skip
  count*, not just pass/fail: a lab whose fixture self-skips when its binary
  does not compile reports 0 failures forever.
- **The CI-lane modules rebuild the shared tree if you forget `-m "not slow"`.**
  Both `test_ci_guards.py::test_ci_coverage_runner_green` and
  `test_ci_asan_lane.py::test_ci_asan_runner_green` are `@pytest.mark.slow` and
  each triggers a real instrumented `make -j` in `/tmp/nginx-1.28.3`, replacing
  `objs/nginx` for every session and the whole fleet. Always deselect slow for
  the fast check. When you *do* need an instrumented or otherwise special build,
  build to a private `--builddir` and point the tests at it with
  `TEST_NGINX_BIN=$BD/nginx` rather than mutating the shared tree — and
  remember a rebuild of the shared binary runs from `/tmp/nginx-1.28.3`, not
  from the repo root.
- **Back-to-back isolated runs of the KDC labs all-skip** on a port-18800
  teardown lag; let it settle and retry, and pass an explicit
  `--basetemp=<scratch>` to dodge the shared-basetemp rotation race.
- **Do not diagnose a PKI problem with a hand-rolled
  `pki_helpers.blitz_test_pki()` + `manage_test_servers start-dedicated`
  fleet.** A stale orphan nginx squatting on 18450–18456 holds boot-time certs
  while the blitz rewrites the CA underneath it, which turns a clean signal into
  a contradiction. Reap first, then measure.
- **This WSL2 kernel accepts `O_DIRECT` on tmpfs** (`/dev/shm`), so the
  "tmpfs rejects O_DIRECT" fallback is not deterministically testable here. The
  unit's security-negative case uses an invalid fd (`fcntl(F_GETFL)` fails)
  instead.

### 1.4 Migrating self-provisioning tests onto pre-started dedicated instances

A standing architectural preference (Rob's, ongoing): move test files off the
per-test spawn/teardown pattern and onto a server instance pre-started once
by `manage_test_servers.sh start-all` and torn down only at suite end, one
dedicated instance per migrated test so isolation is preserved — "100
separate pre-started instances" over "100 self-provisioning tests," to avoid
paying nginx/PKI startup cost per test file. The proven 4-step pattern
(templated dedicated config, `start_dedicated_nginx` registration, a
`settings.py` port/data-root pair, and a fixture rewrite that changes no
assertion) is documented in full at
`docs/09-developer-guide/test-server-migration.md`; by the time this was
paused, ~41 tests had been migrated and validated against the pre-started
fleet. Some suites are deliberately kept self-provisioning and not
candidates for migration: `chaos_mesh` and other tests that restart their
server mid-test, ASAN/ephemeral memory-safety suites, and pure `nginx -t`
config-only suites.

### 1.5 The two-lane (and later four-lane) split

Running the ~5,180-to-8,500-test suite as one `pytest -n N` invocation hits
two traps that each waste a full run (~13 minutes) before you notice them:
relative test paths resolving to nothing under xdist's worker chdir (§1.3),
and `--dist loadgroup` dying on any worker crash. The stable shape that
emerged:

- **Lane A (parallel, `-n 12 --dist load`):** everything except destructive
  and dedicated-instance suites — the bulk of the suite, finishes clean.
- **Lane B (serial, `-p no:xdist`):** self-starting, high-port,
  destructive suites that would starve or kill xdist workers if run inside
  the parallel pool — chaos mesh, chaos mixed-auth, CMS resilience,
  compression/FUSE resilience, evil_actor{,_v2,_v3}, evil_paths, net-fault,
  net-resilience, official-xrootd resilience, phase51 resilience,
  xrootdfs resilience, and everything under `tests/resilience/`.

This later matured into a documented `--pr`/`--fast`/`--nightly` split (see
`testing-infrastructure.md` for the current commands) once profiling showed
the "everything except fault/chaos" scope (~8,519 tests) still ran 513s —
too slow for a <5-minute PR gate — because medium-heavy families
(`clientconf` alone: 355 tests, 62s+) dominate the tail. A narrower
`nightly`-only marker (188 fault tests) was tried and abandoned as too narrow
to close the gap on its own; the working answer was module-level slow-family
auto-marking plus the lane split above. One structural fix from this era:
differential conformance tests that probe *our* server then the *stock*
server sequentially were serializing two independent 5s socket timeouts into
10s per case; running both probes as GIL-released threads (`_run_pair`)
overlapped the waits and cut `conf_framing` from 51.3s to 31.3s (-39%), a
pattern applicable to the rest of the `conf_*` differential families.

### 1.6 Per-test server declaration, and the subset boot that was dead code

Booting all 120 fleet instances for every run is most of the cost of a focused
test. The fix was to make each test *declare* the dedicated servers it uses, via
markers applied by an idempotent codemod (`tools/add_registry_markers.py`, 547
markers across 50 files), and hard-fail at collection when a collected test
touches a server it never declared. The policy — marker syntax, exemptions, the
`REGISTRY_STRICT_DECLARATIONS=0` report-only escape — is in
`tests/configs/REGISTRY_MIGRATION.md` § "Declaring Servers (collection gate)".
Detection is by *port-constant reference*, resolved through an authoritative
port→owning-spec map (`tests/fleet_ports.py`), which is itself linted so no port
value can be owned by two specs. Of the tree, ~4600 tests are serverless, ~1470
touch only the always-on backbone (7 core specs, reached via fixtures and
therefore never declared), and 547 touch a dedicated spec.

Two lessons outlived the migration.

**The opt-in subset boot had never once run.** The fleet started from
`pytest_sessionstart`, which fires *before collection*, so the subset computed in
`pytest_collection_modifyitems` was invisible and `start_registered(None)` booted
all 120 every time — the feature was dead code that read as working. Moving fleet
start to `pytest_collection_finish` fixed it: that runs after `-m`/`-k`
deselection, so the boot set is the exact subset (with `--collect-only`, empty,
attach, remote and worker sessions all skipped). Under xdist the controller never
collects, so it keeps the full-fleet path from `sessionstart`. General form: **a
lazily-computed optimisation whose input is produced after its consumer runs is
indistinguishable from a working one until you measure the boot.**

**Subset selection exposes a whole class of invisible dependency.** A module-level
*autouse* session fixture that waits on a dedicated spec's port is invisible to
per-test attribution — only the test that took the fixture as a parameter declared
the spec, so any `--lf`/`-k` subset from that module *without* that test booted no
such server and the autouse fixture errored every test in the module at its port
wait. The fix was to drop `autouse=True` where there was a single real consumer.
Audit for this whenever a module's tests error at a port-wait fixture only under
subset selection and pass when the whole module runs.

Also fixed in the same lane, both real flakes rather than harness artefacts: a
cluster fixture demanded a redirect to one specific data server, but selection
tie-breaks by registration order and parallel bring-up can register the other
first (25s timeout, last status 4004) — it now accepts either; and a select-wake
helper judged the *first* locate, which is `kXR_error` by design until the
parent-CMS link is up, so it now retries to a deadline.

### 1.7 The host-literal guard decays, so run it in every sweep

A 15-wave sweep removed 1233 hardcoded network host literals (`localhost`,
`0.0.0.0`, `127.0.0.1`, `::1` and friends) from `tests/`, replacing them with
env-overridable constants in `tests/settings.py` (`HOST`, `BIND_HOST`,
`SERVER_HOST`, `HOST6`, `BIND_HOST6`, `url_host()`), so a move to k8s pods is one
config change. The AST guard `tests/test_no_hardcoded_hosts.py` is
zero-tolerance with no baseline.

The migration taxonomy is worth reusing verbatim, because every wave reduced to
it: a **dial/connect target** becomes `HOST`/`SERVER_HOST`/`HOST6`; a
**bind/listen/readiness-probe** target becomes `BIND_HOST`/`BIND_HOST6`; and a
literal that **is the subject under test** — a cert CN/SAN, an SSRF or fuzz
payload, a host ACL rule, an asserted log or metric value, a krb5 principal, a
deliberate numeric-IPv4 forcing, a wildcard `0.0.0.0` bind — keeps its literal and
takes an inline `# net-literal-allow: <reason>` marker. The reason is mandatory;
a bare marker is rejected by the guard's own regex. One addition from the later
burndown: **loopback inside a test network namespace must be annotated, never
routed through `settings.HOST`**, because `HOST` names the host's fleet address
and does not follow into the netns.

Two durable warnings:

- **This is not a one-and-done migration.** The guard was clean on 2026-07-22 and
  **red again with 45 literals across 14 modules by 2026-08-04** — every new test
  module reintroduces them. Run `pytest tests/test_no_hardcoded_hosts.py` as part
  of any test-suite sweep, not once per migration.
- **The guard is necessary, not sufficient.** It scans `tests/*.py` for
  *literals*; it does not check `cmdscripts/*.py` f-string correctness, so two
  migration artefacts reached runtime. A plain string that received a `{HOST}`
  substitution but was never made an f-string passed the literal `{HOST}` to
  curl/xrdcp/nginx-config (find with
  `grep -rnE '(^|[^f])"[^"]*\{(HOST|BIND_HOST|SERVER_HOST)\}'`, then exclude hits
  inside multiline `f"""` blocks); and a `from settings import ...` was injected
  into a *generated standalone script* that nginx runs as its own subprocess,
  where `settings` is not on `sys.path` — `ModuleNotFoundError`, staging fails,
  tape/S3-Glacier residency tests fail. A migrated cmdscript needs a live scenario
  run, not just a green guard.

Marker mechanics that save time: `#` is a valid comment in nginx-config, bash and
`krb5.conf`, so markers work *inside* triple-quoted config blocks (the guard scans
the whole AST node span), but adjacent `Constant` nodes each need their own marker
in their own span. Migrating a module constant means replacing the whole
`HOST = "127.0.0.1"` line with `from settings import HOST` so the name rebinds.

---

## 2. The differential conformance program

The single most productive testing investment in this era: instead of
asserting what we *think* the protocol should do, drive the same operation
against **our nginx server and a real stock XRootD/XrdCl reference** on
identical data trees and treat any divergence as our bug unless proven
otherwise. Framework: `tests/official_interop_lib.py`
(`L.start_pair(base, our_port, off_port)`); design doc
`docs/10-reference/xrootd-interoperability-conformance.md`. errno→kXR
grounding: `XProtocol::mapError` in the stock source tree.

### 2.1 Waves and what each one caught

**Batch 1 (~256+908 tests, 2026-06-24 harness bring-up):** two systemic
harness bugs cleared roughly 240 spurious failures before any real bug
triage could happen — see §2.2. Once those were fixed, 14 real
server/client divergences landed, the sharpest being a genuine **data-loss
bug**: `kXR_rm` on a non-empty directory silently retried with
`recursive=1`, recursively deleting it. Also landed: `kXR_mkpath`/`kXR_async`
parent-create semantics (xrdcp sends `kXR_async`, not `mkpath`, to request
auto-creation — confirmed by grepping `XRD_LOGLEVEL=Dump` wire flags, not
assumption), a cache-flush regression where a wire-format fix elsewhere had
started returning 4-byte file handles but the flush handler still required
the old 12-byte reply (**lesson: rerun the full topology fleet after any
wire-format edit — it can desync an internal peer that wasn't touched
directly**), and an open-on-existing-file case that returned the wrong error
code (`kXR_FileLocked` instead of `kXR_ItExists`).

**Batch 4 (~1,160 tests, real libXrdCl + gfal bindings):** shifted the
oracle from "what stock CLI tools print" to "what the `XrdCl` public API
contract guarantees" — i.e. what gfal/FTS/Rucio actually depend on. Real
`XRootD.client` bindings are driven **out-of-process** via an isolation
worker (`tests/_xrdcl_proxy.py`/`_xrdcl_worker.py`) — importing `pyxrootd`
directly inside pytest deadlocks. Nine divergences fixed, including stat
`id` composition (`(st_ino<<32)|(uint32_t)st_dev`, not bare inode),
`ENOTEMPTY`/`EEXIST` mapping to `kXR_ItExists` not a generic FS error, and a
`kXR_fattrList` bug that leaked an internal `user.U.` prefix into
client-visible attribute names (breaking list→get round-trips). One
deferred/non-bug: pgwrite CSE-retransmit — both sides *detect* a corrupt
page, they just recover differently (stock retransmits, we hard-fail); not
data loss, left as documented behavior divergence.

**Full-suite triage waves (2026-06-24):** once the harness itself was fixed,
the overwhelming majority of "conformance failures" turned out to be **stale
test expectations**, not server bugs — verified one at a time against a live
stock reference. Recurring categories: unknown-opcode error code
(`kXR_InvalidRequest`, not `kXR_Unsupported`), `kXR_statx` wire format
(one flag byte per path, newline-separated, no size field), `mkdir` on an
existing directory being POSIX-correctly `kXR_ItExists` (stock's apparent
idempotency is a same-process oss-namespace-cache quirk, not a wire
contract), and pre-login `kXR_ping` being **correctly rejected** (both our
dispatcher and stock route every non-auth request through the login gate
before login — several tests had wrongly assumed ping was exempt and used it
as a pre-login liveness probe). One real gap did surface in this wave:
`query config version` echoed the literal string `"version"` instead of a
version string with digits. The sharpest harness lesson of the wave: `kXR_sigver`
is a request *prefix*, not a request with its own reply — a valid, no-op
envelope draws no response at all (matching the reference `ProcSig`), but 20
tests waited for a `kXR_ok` ack anyway, hung, hit their 30s timeout, and
crashed their xdist worker; fixed with no-wait test helpers rather than any
server change.

The macaroon batch (12 tests) looked like a format mismatch but wasn't — the
HMAC chain, secret, and expiry all validated. The real cause was
issuer-pinning: the server pins a macaroon's `location` claim to the
configured token issuer (fail-closed by design), but macaroons minted by the
server's own endpoint weren't stamping that issuer, so the server's **own
issued macaroons failed re-validation against its own pin** — a genuine
latent bug, fixed by stamping the configured issuer instead of deriving
`location` from the request Host header.

### 2.2 Two harness bugs that were masquerading as ~250 product bugs

Before any of the batch-1 divergences could be trusted, two harness defects
had to be found and fixed — a reminder that a conformance suite's own
plumbing is load-bearing:

1. **Fixed ports under `xdist --dist load` caused cross-talk.** Each `conf_*`
   module owns a fixed port pair via a module-scoped fixture; under
   `--dist load`, tests from one module scatter across workers, and *every*
   worker that picks up one instantiates the fixture — N workers try to bind
   the same port. The readiness wait only checked that *something* was
   listening, so the losing worker silently talked to the winner's data
   tree: writes landed in tree A, reads looked in tree B,
   `FileNotFoundError`. Fixed with `worker_port(base)`, which shifts every
   conf port into a private per-worker band, lifted clear of the shared
   fleet's port range. This single fix cleared ~240 of the ~250 batch-1
   failures.
2. **Real data-loss bug, found once the noise cleared.** `xrootd_upload_resume`
   defaults on: every writable open stages to a `.xrdresume.<hash>.part`
   file written from empty, renamed over the final file on close. For a pure
   update-in-place open (not create, not truncate) of an already-committed
   file, this is a read-modify-write — but staging started from an *empty*
   partial, so unwritten byte ranges were zero-filled and the original bytes
   were lost on the commit rename. Diverges from stock, which always edits
   in place. Fixed: an update-in-place open of an existing regular file
   whose resume partial does not yet exist skips resume staging and opens
   the final file directly; only a genuine reconnect (partial already
   present) still stages.

### 2.3 WLCG x509 and token conformance — from spec compliance to source-level parity

Two escalating x509 efforts landed on `main` (2026-07-06), both starting
from the WLCG CA/token profile spec and ending in source-level comparison
against the real XRootD codebase:

- **First pass** (`wlcg_x509_conformance_landed`): implemented Globus EACL
  `signing_policy` enforcement, RFC 3820 §3.8 proxy-chain monotonicity
  (limited→full escalation rules), and configurable CRL modes
  (off/try/require, default `try` — a deliberate behavior change from the
  old implicit require-when-present). ~100 conformance checks across 3
  layers (C unit, pytest e2e over the shared davs:// verifier, differential
  vs stock XrdHttp). The differential run found **3 real divergences**:
  stock XrdHttp accepted out-of-namespace certs, wrong-CA-policy certs, and
  *revoked* certs that we correctly reject in the same baseline CA-dir
  configuration.
- **Second pass** (`wlcg_x509_500_conformance`): scaled to 500+
  clause-indexed tests plus a hyper-detailed source-level comparison against
  XRootD v6.1.0 (pinned checkout at `/tmp/xrootd-src`, tag v6.1.0). Verified
  from source, not just black-box behavior: stock XRootD does **not**
  enforce `signing_policy` at all, does **not** enforce limited-proxy
  monotonicity, only *warns* on CRL expiry rather than rejecting, and
  `XrdHttp`'s TLS layer does no GSI chain or signing-policy verification
  whatsoever (TLS-layer verify only). Conclusion, stated plainly in the
  memory and worth keeping: **we are stricter than stock in every area where
  we differ, and stricter in none where it matters** — every deliberate
  divergence is recorded in one auditable register
  (`tests/clauses/_decisions.py`), not scattered xfails. Final differential
  run against 420 davs:// wire cases: 104 divergences, all falling into four
  explained buckets (signing_policy that stock doesn't enforce, CRL being
  TLS-only for stock, DN handling, weak-crypto acceptance).
- **WLCG token (bearer/JWT) suite** (`wlcg_token_conformance_suite`,
  2026-07-06): 103 wire+unit tests plus a hostile-token forge
  (`tests/tokenforge.py`). Found one real authorization gap — WebDAV
  GET/HEAD/PROPFIND skipped scope checking entirely, meaning a token with no
  read scope could still read — fixed by generalizing the existing
  write-scope check to cover reads and calling it in the access phase. Also
  fixed a silently-dropped scitokens config key (`authorization_strategy`
  vs. the wrong `authz_strategy` that was actually being read), added
  configurable clock-skew tolerance (expiry grace only — `nbf` stays strict
  by design), and generalized JWKS key lookup to try all keys when a
  key-less token omits `kid` (was previously keys[0]-only, silently failing
  rotation). Net conclusion: root:// token validation is robust across
  alg-confusion, tampering, and boundary-condition attacks — the suite
  mostly validated existing behavior rather than uncovering bugs, with the
  WebDAV read-scope gap the one exception that mattered.

### 2.4 Multiuser permission conformance — the cache-transparency invariant

`tests/mu_authz_lib/` + `tests/test_mu_*.py` (F1-F9 families, ~226 cells)
proves a single invariant: **`verdict_cached == verdict_cold`** for every
(principal, path, operation, protocol) combination, with a cold direct check
as the oracle. This caught **6 rounds of real cross-user authorization
leaks** — cache-serve auth bypass, mode leaks on cache/staging artifacts,
WebDAV authdb/VO-ACL parity gaps, a read-open existence oracle, WebDAV VOMS
extraction gaps, and write-side staging-temp/sidecar-file visibility leaks.
All landed and green; full writeup (architecture, family map, leak taxonomy)
now lives in `docs/09-developer-guide/multiuser-conformance.md` and
`docs/09-developer-guide/cache-authz-best-practice.md` — this is the one
class of finding worth reading there in full, since a cache-serve auth
bypass is a real per-user data-exposure bug class, not a test nicety.

### 2.5 Coverage-gap audit — four real bugs found by asking "what's untested"

A 13-area parallel audit (142 raw gaps, ranked) deliberately went looking for
dark corners rather than differencing against stock, and found four real
source bugs: `token/validate.c`'s `json_get_string()` rejected a JWT `aud`
claim expressed as a JSON array (the common RFC 7519 §4.1.3 form), causing a
false 403 — fixed with a new `json_string_or_array_contains()` helper.
WebDAV PUT (`webdav/put.c`) opens the target `O_TRUNC` in place (unlike S3,
which stages to a temp file and renames); on an inflate/write failure it
closed the fd without unlinking, leaving a corrupt, readable 0-byte object
behind — fixed by unlinking on the failure path. S3 `UploadPartCopy`
(`src/s3/handler.c`) was **100% non-functional** — always returned
`NoSuchUpload` — because `fs_path` was overwritten with the part-file path
before the multipart-upload directory was re-derived from the destination
key; fixed by reordering. Once that path was live, it turned out to use raw
`open()`/`stat()` calls with only string-based path validation, giving a
symlink-escape to arbitrary files (e.g. `/etc/passwd`) — fixed with
`xrootd_open_confined_canon()` (openat2 `RESOLVE_BENEATH`). The audit's
standing lesson: grep `\bopen\(|\bstat\(` in `src/s3` and `src/webdav`
periodically for more raw-syscall confinement gaps outside `src/fs/backend/`.

### 2.6 Protocol / topology conformance harnesses

- **`test_conformance_topologies.py`** runs the entire conformance suite
  through every network shape (proxy, 2-hop mesh, CMS cluster,
  mirror-shadow-replay) as subprocesses. Found and fixed a **cluster
  infinite-redirect loop** (the manager ignored the client's `?tried=` list
  and kept re-redirecting to the same data server forever until "Redirect
  limit reached") and a **mirror shadow-replay fidelity bug** (verbatim
  frame replay broke for handle-based ops and write/create opens against a
  stateless shadow session — fixed by only replaying self-contained,
  side-effect-free requests).
- **`test_integrity_matrix.py`** proves bytes survive exactly and server
  checksums agree with a local recompute, across root/https/S3 over every
  topology. Landed the checksum-through-mesh fix: `kXR_Qcksum` now correctly
  redirects through manager-mode CMS-locate and cache-origin lookups instead
  of silently failing when the query couldn't be answered locally.
- **The P0 protocol suite** (12 files, root/CMS/xrdhttp,
  `docs/09-developer-guide/protocol-test-design.md`) caught a real pgread
  offset-alignment parity bug and proved POSC (persist-on-successful-close)
  abort cleanup is correct (temp file unlinked ~0.02s after disconnect via
  the normal close path — an apparent "leak" was actually a test race that
  checked once without polling).
- **Manager-mode redirect gaps (May 2026, found during general suite work).**
  `kXR_stat` and `kXR_dirlist` had no `manager_mode` redirect at all and fell
  through to the local filesystem instead of being routed to the registered
  data server (`src/read/stat.c`, `src/dirlist/handler.c` — fixed by adding
  the same `xrootd_srv_select()` redirect block used elsewhere). Separately,
  the normal write-open path's `allow_write` gate fired *before* the
  manager-mode redirect check (`src/read/open_request.c`), so a manager
  server tried to serve writes locally and returned `kXR_fsReadOnly` instead
  of redirecting them to a DS — fixed by adding `&& !conf->manager_mode` to
  the gate, matching the pattern the TPC path already used.
- **`kXR_readv`/`pgread`/`pgwrite` wire-parity fixes**: an XrdCl client that
  sends a `readv` element larger than `readv_ior_max` used to hang for 90s
  (our server intentionally serves oversized elements *short*, for a
  feature our own native client relies on, but XrdCl can't handle a short
  element and just waits) — resolved by fixing the *test client* to never
  send oversized elements rather than breaking the server feature. Real bugs
  fixed alongside: `pgread` read a negative length as unsigned (silently
  capped instead of rejected) and `pgwrite`'s status-response "info" offset
  echoed the wrong value (next-expected instead of request offset, per
  reference `do_pgWrite`).

---

## 3. Chaos, reload, and resilience testing

### 3.1 Chaos mixed-auth exposed a wholly dead auth path

`tests/test_chaos_mixed_auth.py` hammers a small mesh whose *upstream* auth
mixes X.509 and SSS while backends restart underneath it. This uncovered
that **SSS proxy-upstream authentication against our own origin had never
worked at all** — dead code, because nothing had ever exercised it. Three
bugs, all in the proxy's upstream-auth path: the login-security hint parser
only handled the `ztn` protocol advertisement, not `sss`; the SSS keytab was
only loaded when the proxy's own inbound auth was SSS (not when only the
*upstream* leg needed it); and the outbound `kXR_auth` request left its
16-byte credential-type field zeroed instead of `"sss\0"`. Fixed and
validated end-to-end, with a 12-worker concurrent storm (4 backend restarts)
added as a regression gate.

### 3.2 Fast-teardown-during-reload lost an in-flight streaming read

`test_chaos_mesh::test_tier2_reload_during_stream_read_preserves_md5` failed
deterministically at a variable offset (21-27 MB) after a mid-stream reload.
Root cause was a real product bug, not environment: the graceful-shutdown
fast-teardown path (`ngx_exiting` handling in
`src/protocols/root/connection/recv.c`) force-closed a draining worker's
connection between `kXR_read` chunks even when a file was still open
mid-transfer — the shutdown gate checked outstanding-write/in-flight counts
but not open file handles. For a streaming slice-cache read through a
Tier-1 proxy, that forced a mid-stream reconnect that lost the in-flight
fill, surfacing as a spurious `kXR_NotFound` well after the reload actually
happened (reads survive the reload itself; the *next* inter-chunk idle park
is what got caught). Fixed by gating both the exiting-teardown and the
idle-marking on whether the connection has an open file handle, so an active
transfer finishes on the old worker (normal graceful reload, with
`worker_shutdown_timeout` as backstop). Verified 10/10 on the specific
repro plus full regression (chaos mesh 6/6 x4, reload/shutdown-resume 13/13,
210 framing/readv/write/cache/gsi tests).

A process lesson from the same session, worth keeping: this box runs
**multiple concurrent Claude sessions on one working tree**. `git commit
--amend` moved HEAD out from under a concurrent session's WIP and bundled
their uncommitted files into this session's commit by accident (nothing was
lost, just mis-attributed). Rule: never amend on a shared tree; stage
explicit pathspecs, never `git add -A` (it will grab a concurrent session's
files).

### 3.3 Chaos/discovery ordering and other harness-shape findings

`test_delayed_cms_start_registers_data_server` needs the data server to
start *before* its CMS manager, to exercise the retry-then-succeed
registration path; the harness previously started the manager first,
eliminating the failure window it was meant to test — fixed by reordering
with a deliberate `sleep 4` between them.

Resilience/fault-proxy tests are, by explicit directive, required to be
fully self-contained: their own nginx + reference xrootd on a unique
high-port block, their own PKI and data root, auto start/stop per run,
living in `tests/resilience/` rather than depending on the shared fleet —
the shared fleet is flaky enough on its own (readiness-probe timing,
stale squatter processes on reused ports) that resilience tests riding on
it produce false signal either direction.

### 3.4 Phase-51 cross-protocol resilience batch

A 13-workstream hardening pass (2026-06-23) closed several real stall/DoS
classes discovered by resilience testing pressure: unbounded proxy
upstream-write stalls (now default 60s), unbounded native-TPC transfer time
(now default 24h, still overridable to unlimited), missing OCSP-fetch
socket timeouts (a black-holed OCSP responder could previously freeze a
worker forever — non-blocking connect + poll deadline added, since
`SO_SNDTIMEO` alone does not bound `connect()`), unbounded CMS frame
processing per event-loop wakeup (capped at 64 frames then yields, so one
flooding peer can't monopolize a worker's event loop), and a real durability
gap (`fsync` before rename on staged-file commit, fail-closed on fsync
error, covering both WebDAV PUT and S3). Also added: per-worker auth-gate L1
cache to remove a SHM spinlock from the hot GSI path, a CMS per-source-IP
connection cap, a pending-locate reaper, NSS/reverse-DNS circuit breakers,
and a per-worker in-flight GSI-handshake admission cap. All landed
build-clean under `-Werror`, validated against ~429 tests with zero wire
format changes.

---

## 4. Production/reliability postmortems

### 4.1 The "host overloaded" excuse — banned, with teeth (2026-07-15)

For an extended period, test flakiness, timeouts, and elevated system load
on the dev box were written off as "the WSL2 box is overloaded" or "load
flake, environmental, not code" and pushed through with retries and serial
re-runs. The real cause: an **uninitialized reaper timer crash-looped nginx
on every launch** (fixed in commit `66efecd0`), and `systemd-coredump`
captured a full core dump on every single crash-loop restart. The load
*was* the bug — its own symptom, not weather. Tests that ran in the brief
alive window between crashes would pass, so the retry ladder laundered a
severe crash-loop into apparently-green suites for weeks, and multiple
memories from that period recorded the false conclusion "flaky under load,
not code" (several are cross-referenced and correction-banner'd:
`evil_actor_v3_rounds_scaling`, `full_suite_run_recipe`, `test_harness_gotchas`,
`test_suite_fast_tier`).

**Standing rule, not optional:** "host load" is the *absence* of a
diagnosis, not a diagnosis. Before attributing anything to load: check
`coredumpctl list --since=-1h` for crash dumps, check worker PID churn
(`pgrep nginx` sampled twice, master restart counts), and check `error.log`
for repeated startup banners. A test that "passes on serial re-run" is not
thereby exonerated — a crash-looping server also passes whenever the test
happens to land in its alive window; re-run success is evidence of
nondeterminism, not of environmental cause. Do not write "environmental,
not code" into any memory or doc without naming an actual mechanism.

### 4.2 Nginx POSIX-semaphore shmtx stall (see full postmortem separately)

Referenced here for completeness since it's a load/lockup-class incident:
stock `ngx_shmtx_create(..., NULL)` silently enables a semaphore-based
shared mutex whose wakeup path loses wakeups under cross-worker contention —
a worker can block in `sem_wait` forever *with the lock actually free*,
freezing its entire event loop (measured 60-450s connection stalls on the
hot `kXR_open` path). Every module SHM mutex now goes through
`brix_shm_table_alloc()` (spin+yield, never the semaphore mode) — this is
now CLAUDE.md invariant #10. Full analysis:
[postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md).

### 4.3 Reboot/lockup audit — SHM and lock-file state that doesn't survive a killed worker

A focused 2026-07-01 audit asked one question: what SHM/lock state can be
permanently stranded by a `SIGKILL`ed worker, accumulating across reboots?
Found and fixed four real classes:

1. **Dead-holder SHM mutex stranding.** `ngx_unlock_mutexes()` (nginx's
   per-worker-death force-unlock) only clears `&sp->mutex`, never a mutex
   embedded elsewhere in a slab-allocated table — a worker killed
   mid-critical-section strands the embedded lock forever, surviving even a
   reload. Fixed by binding the mutex to the slab's own lock word.
2. **Cache-fill lock-file dead-owner stranding.** The per-file fill lock is
   an `O_CREAT|O_EXCL` lock file (not a kernel-auto-released fcntl/flock),
   unlinked only on a *normal* fill exit. Nothing reclaimed a killed
   worker's orphaned lock file — every later request polled for up to
   `cache_lock_timeout` (default 300s) and then permanently returned
   `kXR_FileLocked`, pinning a thread-pool thread on every retry until pool
   exhaustion. Fixed: reclaim a lock whose owner pid is provably dead
   (`kill(pid,0)==ESRCH`) or whose content is stale/torn beyond the timeout;
   a live owner is never reclaimed, and the reclaim race is benign because
   fills always write to a verified `.part` file with an atomic rename.
3. **libcurl cache-origin transport had no stall timeout.** Only
   `CURLOPT_CONNECTTIMEOUT` was set; a stalled-but-connected origin blocked
   `curl_easy_perform` forever on a fill thread-pool worker, and enough
   stalled fills exhaust the whole pool, stalling the fleet fleet-wide.
   Fixed with `CURLOPT_LOW_SPEED_LIMIT`/`CURLOPT_LOW_SPEED_TIME`. A source-lint
   test now asserts every curl transport in the tree sets a stall bound.
4. **Rate-limit in-use gauge leak across reload.** The rate-limiter's
   `in_flight`/`open_files` gauges increment on acquire but only decrement on
   a matched release; a worker killed mid-request never releases, and — worse
   — the SHM node is *adopted* across a config reload (live buckets
   intentionally survive reloads), so the leak accumulates every restart
   until the key is throttled forever, with no owning pid left to
   liveness-check. Fixed by zeroing both gauges specifically on reload
   adoption (the windowed rate/bandwidth buckets themselves are deliberately
   preserved — a reload must not be a rate-limit bypass).

Audited clean with no fix needed: all 13 SHM mutexes in the tree, checked
transitively for ABBA ordering and blocking I/O held under a lock — none
found; every critical section claims state into a local batch and acts
outside the lock. **Generalized pattern for any future audit of this
class:** an on-disk existence lock (`O_EXCL`/`mkdir`-based) needs an
explicit dead-owner-or-age reclaim path; fcntl/flock locks self-heal on
process death and don't need one; spin+yield SHM mutexes must keep their
critical sections to pure fixed-slot scans; any blocking I/O performed on a
thread-pool worker needs a timeout or it can exhaust the whole pool.

### 4.4 Read-after-large-readv use-after-free (load-test-discovered)

The load-testing harness (`run_load_test.sh`) surfaced a remotely-triggerable
crash: a large `kXR_read` immediately followed by a large `kXR_readv` on the
*same* connection corrupted `ctx->read_scratch`
(`SIGSEGV`/`free(): invalid pointer`). Not a size-math bug — bounds were
textually consistent — it was a genuine use-after-free: a Phase-31
memory-budget helper (`xrootd_trim_scratch()`) freed and reallocated
`read_scratch` on every fresh request, leaving the *next* readv's scratch
pointer dangling. Confirmed by bisection (remove the trim call → 8x
read+readv survives byte-exact; restore it → crash reproduces). Fixed by
disabling the trim call with an explicit security note that Phase-31 was
left incomplete (only the trim landed; the windowed-read replacement that
was supposed to make trimming safe was never built) — anyone re-attempting
Phase-31 scratch trimming needs to build that replacement first, not just
re-enable the call.

### 4.5 Rate-limiter drain bug found by paced metadata stress

`test_metadata_stress.py` (a *rate-paced*, not max-throughput, metadata-op
stress test) found that the rate limiter's throttle branch advanced the
bucket's timestamp but never wrote back the drained "excess" counter back to
the SHM node — only the accept branch persisted it. Every throttle event
reset the drain clock against a stale, pegged excess value, so the bucket
effectively never drained and the *served* rate collapsed to a small
fraction of the configured limit (a nominal 30 req/s limit served only ~7
req/s under sustained load). One-line fix in the throttle branch.

### 4.6 In-place-write data loss (see also §2.1)

Worth restating alongside the other production incidents even though it was
found via the conformance harness: resume-staging a pure update-in-place
open from an empty partial zero-filled every byte range the client didn't
explicitly rewrite, silently destroying previously-committed data on commit.
This is the sharpest data-loss bug this era found and the reason "verify a
wire-format or staging change against a full read-modify-write cycle, not
just fresh-write and fresh-read" is now a standing review question for
anything touching `xrootd_upload_resume`.

---

## 5. Load and performance testing

### 5.1 The perf harness and its own footguns

`tests/run_load_test.sh` / `load_test.py` / the paired `nginx.perf.conf` /
`xrootd.perf.conf` are a self-contained perf harness, deliberately not part
of `start-all`. Two harness bugs cost real time before numbers could be
trusted: `nginx -s quit` under `reuseport` + `worker_processes auto` orphans
workers (each independently holds the reuseport socket, so no single
process's cmdline lets a pattern-match kill find it) — orphans accumulated
across runs, and since PKI regenerates every run, stale-cert orphans caused
~135s GSI handshake storms that looked like "nginx is 200x slower" until
traced to leaked processes, not a code regression. Fixed with a
process-group kill via the pidfile. Separately, the readiness probe for the
reference xrootd used `sleep 1; ps | grep`, racing xrootd's own double-fork
startup and reporting false "failed to start" — fixed to wait on the actual
listening port.

A methodology finding worth keeping: the default benchmark compared
nginx-with-TLS against xrootd-with-cleartext (an apples-to-oranges
comparison flattering neither side honestly). A fair cleartext-vs-cleartext
comparison shows nginx **matches or beats** native xrootd for a single
1 GiB `root://` read stream — meaning the pipelining refactor under
consideration (Phase-29) is not justified purely by n=1 throughput; its
value case has to come from concurrency, not single-stream speed.
`--data-tls on` on the native xrootd side is currently misconfigured in the
harness (0 successful ops) and not yet fixed — treat any TLS-on comparison
number from this harness as unusable until that's addressed.

### 5.2 The apples-to-apples nginx-vs-native comparison

`run_load_test.sh both --suite root-gsi` runs the posix-VFS-backed
nginx-xrootd module against native xrootd on the same `oss.localroot`,
self-contained under `/tmp/xrd-load`. Two measurement traps: `--data-tls on`
fails the handshake entirely on the native side (unrelated to our module —
a native XRootD TLS-data configuration issue), so `--data-tls off` is the
only currently-valid comparison mode; and the default `--read-sink tempfile`
writes the full read payload back to client disk, making the whole
measurement client-disk-bound rather than server-bound (~90 MiB/s
regardless of server) — `--read-sink devnull` is required for a real
server-bound number. With both traps avoided, single-stream 1 GiB read:
nginx-xrootd ~297 MiB/s vs native ~242 MiB/s (nginx ~1.23× native on the
posix backend, single stream).

### 5.3 CPU flame graphs and where the cycles actually go

`tests/profile_load.sh read|write|both [concurrency]` wraps the perf harness
with `perf record` + FlameGraph rendering, isolated to the nginx module
process tree (not xrootd). On this box, software `task-clock` events are
required (no working hardware PMU under this custom WSL2 RT kernel) and
DWARF call-graph unwinding is required (the module builds without frame
pointers) — both non-default `perf` options that silently produce useless
output if left at default. Findings at c=64: on-CPU time under **read**
load is dominated by `pread64` plus per-page CRC32c computation
(`xrootd_crc32c_copy_value`), and under **write** load by the raw
`pwrite64` syscall — both on the AIO thread-pool workers, not the nginx
event loop. This matters for any future perf work: the event loop itself is
not the bottleneck under this workload shape; the thread-pool I/O path is.

### 5.4 Load-correlated flakiness needs a re-run lane, not inline retries

Roughly 0.3% of the full suite transiently fails only under a saturated
worker pool (shared single-worker daemons responding slowly under
concurrent load). `run_suite.sh` handles this with a dedicated re-run lane
that re-runs *only* the failures on a quiet box (`--lf`, no new load) — a
genuine load flake passes alone; a real bug stays red. Inline `pytest
--reruns` is the wrong tool for this specific class, because the immediate
retry lands inside the same saturated window and doesn't actually change
conditions.

---

## 6. The k8s test lab and remote-suite work

Built 2026-07-04: a portable minikube + Helm test lab under `k8s-tests/`
(11 charts, `helm unittest` 43/43), driven by `k8s-tests/xrd-lab` — spins up
namespaced profiles (`brix-<profile>`), builds images in-cluster (no
external registry needed), supports a dry-run preview mode. All live smoke,
authority, chaos, fleet, read-only, and CMS-registration gates pass, verified
client-observably (real `xrdcp`/`xrdfs` against ephemeral pods), deliberately
**not** via pytest for those particular gates.

Separately, `k8s-tests/remote-suite/` runs the *actual* ~390-file pytest
suite from a dedicated client pod against a remote "mega" server pod (every
topology's ports collapsed onto one pod) — reached feature-complete status
(390/390 files handled: adapted, verified-ok, pure-remote, or explicitly
remote-skip; WebDAV 120/120 with zero skips). This required `conftest.py`'s
existing `TEST_SERVER_HOST` remote mode (skip local fleet start, connect to
a given host) plus new client-side plumbing for a Python-version split:
pyxrootd's EPEL binding is only ABI-compatible with Python 3.9, but the
suite needs 3.12 for modern union-typing syntax, so pytest itself runs on
3.12 while the `XrdCl` worker subprocess is pinned to 3.9
(`XRDCL_WORKER_PYTHON`). A GSI-over-WebDAV 403 in this environment traced
back to Kubernetes `ConfigMap`s silently dropping symlinks — CA-directory
subject-hash symlinks (`<hash>.0`) have to be materialized into real files
before being loaded into a ConfigMap, or OpenSSL simply can't find the CA.

Non-blocking follow-ons noted at the time: a full green in-cluster suite run
was blocked by a **local WSL2 sandbox defect** (a dead XrdCl-proxy worker
that fails identically outside k8s — not a lab defect), config backfill for
~87 more dedicated fleets, and a live Rook-Ceph backend (feasibility already
confirmed: `/dev/fuse` is reachable from a privileged pod, the operator
itself just wasn't stood up).

---

## 7. Open items carried out of this era

| Item | Class | Where tracked |
|---|---|---|
| HTTP-TPC `TransferHeader` CRLF/control-char injection rejection untested (needs a live TPC server + raw injection) | test coverage gap | `docs/09-developer-guide/testing-infrastructure.md`; source memory `coverage_gap_audit` |
| Native-TPC key replay untested | test coverage gap | same |
| WT-flush-failure durability config exists (`nginx_wt_sync_brokentls.conf`) but zero tests reference it | test coverage gap | same |
| Phase-31 windowed-read replacement never built; `xrootd_trim_scratch()` stays permanently disabled until it is | open bug / design debt | §4.4 above |
| `run_load_test.sh --data-tls on` misconfigured on the native-xrootd comparison leg | perf-harness gap | §5.1 above |
| krb5: handles leak on reload (no `free_context`/`kt_close`/`free_principal`, currently suppressed in `tests/lsan.supp`); no replay-cache control directive; no `docs/06-authentication` kerberos page | module hygiene | `krb5_testing_deps` |
| `start-all` returns 0 even when a server fails to bind (warn-only, no per-server readiness check); `force_stop_nginx` is pidfile-based and misses kill-9-orphaned servers | harness gap | `full_suite_run_2026_07_07` |
| macaroon POST `/.oauth2/token` returns 403 (token-scope check runs path-write-scope on the token endpoint itself) | peer-owned, unresolved at time of writing | `full_suite_run_2026_07_07` |
| 9 test files fail pytest *collection* on Python 3.9 (`dict \| None` annotations) | test-env gotcha, pre-existing | §1.3 above; `lessons-migration-era-2026.md` §13 |

---

## 8. Non-UTF8 byte-input codec correctness suite + `urlencode` NUL bug (2026-08-02)

`tests/test_nonutf8_input.py` — **2946** pure fast-lane cases proving the four pure
kernels every user-supplied byte crosses before auth/storage handle non-UTF8
input *byte-exactly*:

  1. the shared percent-codec `brix_http_urldecode`/`_urlencode`
     (`src/core/compat/uri.c`, the decode surface under WebDAV path+query, S3 SigV4
     canonicalisation, and XrdHttp paths);
  2. the XRootD CGI-opaque **byte** gate `brix_opaque_illegal_byte`
     (`src/protocols/root/path/opaque_validate.c`);
  3. the XRootD CGI-opaque **schema** gate `brix_opaque_schema_check` (same file) —
     the Tier-2 key/type validator whose *offending-key echo* is logged/forwarded, so
     its byte-transparency on a non-UTF8 key, and its type-rejection of every non-digit
     value byte, are part of "handled correctly";
  4. the internal-name (invisible sidecar/temp) gate `brix_is_internal_name`
     (`src/fs/path/reserved_names.h`, header-only `static inline`) — a non-UTF8 basename
     ending in a reserved suffix must still be hidden (else its existence/size/mtime
     leak), and no lone control/high byte may be misclassified as internal.

(The suite began at 1620 cases over kernels 1-2; the 2026-08-02 expansion added
kernels 3-4 — schema gate and internal-name gate — for the 2946 total.)

**Why it is not a duplicate.** `tests/fuzz/fuzz_urlcodec.c` is a *random* libFuzzer
target that only asserts crash-safety under ASan; the live `path-pct-XX` sweeps in
`fuzz_corpus.py` check server *responses*, not exact codec bytes. Neither pins the
byte-for-byte contract. This suite does, against an independent Python oracle
(`tests/cmdscripts/nonutf8_codec.py`) — a differential check, not a copy of the C.

**Shape (mirrors the `c_*_units` pattern).** A data-driven C harness
(`tests/c/nonutf8_codec_harness.c`) links the *real* `uri.c`/`hex.c`/`opaque_validate.c`
(and `#include`s the header-only `reserved_names.h`) and speaks a hex line protocol on
stdin (`d` decode / `e` encode / `r` round-trip / `o` opaque-byte / `s` opaque-schema /
`n` internal-name), so a Python suite can drive thousands of byte vectors through the
production code with no nginx runtime and no fleet. All I/O is hex so NUL/CR/LF/0x80-0xFF
travel unambiguously. The suite is pure (zero fleet-boot seed), so it rides
`-m "not slow and not serial"`; 2946/2946 pass serially (~1.9s) and under xdist `-n8`
(~2.9s), and the harness compiles clean under `-Wall -Wextra -Werror`.

Coverage — kernels 1-2 (codec + opaque byte gate): `%XX`→byte transparency (upper/lower
hex), literal high-byte passthrough, `%00` reject-vs-pass per `REJECT_NUL`, embedded-NUL
C-string truncation (the strlen view is exactly what downstream callers see), malformed-`%`
preserved-verbatim, `+` handling, overflow/BADARG boundaries, `encode` vs RFC 3986 +
`safe_extra`, `encode∘decode == identity` round trip over every byte and a battery of
non-UTF8 sequences (overlong, surrogate, out-of-range, truncated, BOM, Latin-1, CP1252,
Shift-JIS/GB18030-ish, deterministic high-byte blobs), and the opaque gate's exhaustive
0x01-0xFF verdict + offending byte. Kernel 3 (schema gate): every non-NUL byte as a lone
unrecognized key must be echoed back verbatim (offending-key byte-transparency for a
clean rejection log); `oss.asize` type enforcement rejects *every* non-digit value byte
(0x01-0xFF minus the ten digits) as `BAD_TYPE`; a recognized-namespace value accepts an
arbitrary high byte (schema is orthogonal to byte hygiene — Tier-1's job); plus structure,
NUL truncation, nested-query scope, dot-guard (`xrd` ≠ `xrd.`), and keybuf truncation.
Kernel 4 (internal-name gate): exhaustive negative over 0x01-0xFF (no lone byte is
internal); a reserved suffix with a non-UTF8 *stem* is still hidden; a suffix polluted by
a trailing non-UTF8 byte is *not* (no over-hiding); the upload-temp infix survives non-UTF8
neighbours; and NUL truncation that both hides (`a.cinfo\0.txt`→hidden) and reveals
(`a.txt\0.cinfo`→visible). The oracles are independent Python reimplementations
(differential checks), and the internal-name curated table is cross-asserted against the
oracle at import so an oracle drift fails collection rather than silently passing.

**Bug it caught (fixed same change).** `brix_http_urlencode` passed a NUL byte through
*literally* instead of encoding it to `%00`: `strchr(unreserved, c)` with `c=='\0'`
returns a pointer to the `unreserved` string's own NUL terminator, so a NUL input byte
was misclassified as unreserved and copied through. A literal NUL in a canonical S3
signing string or a generated URL is a truncation / smuggling primitive. Fixed with a
`c != '\0'` guard before the `strchr` tests (`src/core/compat/uri.c`); documented in
`docs/07-security/hyper-hardening-plan.md` C-1 item 5. TRAP for anyone touching a
`strchr`-based membership test: `strchr(set, 0)` is always a hit — guard `c != '\0'`
whenever the scanned byte can be NUL.

---

## 9. CMS/AAA federation join under network noise (2026-08-05)

**What was untested.** BriX had heavy CMS coverage — hostile framing, wire PUP
conformance, mesh interop, and (phase-97) cross-implementation manager parity.
All of it spoke to its peer over a *clean loopback socket*. A real CMS AAA site
reaches its redirector over a WAN, and the join is a handshake across that link,
so nothing had ever asked whether a node can join, or stay joined, while the
link is impaired. Separately, nothing on the node could answer "am I still in
the cluster?" — `brix_cms_read_timeouts_total` reports a symptom fired, not
membership.

**The oracle came first.** Three fields were added to the Phase-51 resilience
block: `brix_cms_logins_total`, `brix_cms_connect_failures_total`, and the gauge
`brix_cms_registered_links`. The gauge is emitted by hand with `mw_printf`
rather than through `mw_emit_scalar`, which hard-codes `# TYPE … counter` — the
`frm_metrics.c` pattern. A gauge mislabelled as a counter is worse than no
metric at all, because `rate()` over it returns plausible nonsense.

**TRAP — a refused connect does not necessarily surface at `connect()`.** The
three obvious failure sites in `src/net/cms/connect.c` (the
`ngx_event_connect_peer()` error branch, the connect deadline, the login write)
were all instrumented first, and a deliberately refused dial still counted
**zero**. A standalone probe pointed at a dead port showed why: the log carried
`recv() failed (111: Connection refused)` while `grep -c "will keep retrying"`
returned 0, proving the `connect_peer` branch never ran. On loopback — and on
any path where the peer resets rather than drops — the refusal is reported on
the **read** side (`cms_recv_accumulate` → `cms_conn_fail`, `src/net/cms/recv.c`),
a fourth site nobody would think to instrument. The fix was to stop counting at
failure sites altogether and count in `ngx_brix_cms_disconnect()`, the one
funnel every failed join passes through exactly once: `logged_in` set means a
link is leaving the cluster (decrement the gauge), clear means the dial never
became a link (increment failures). Generalisable: when an error can be
delivered by more than one event handler, instrument the teardown, not the
detection.

**The suite.** `tests/test_cms_aaa_join_noise.py` — 13 tests, fully
unprivileged. The WAN is `client/bin/brix-fault-proxy` (phase-89), a userspace
TCP relay with a live control port, which is what removes the need for `netem`
and therefore for root. Topology: a raw kXR client drives the node's data plane,
the node dials a `ManagerPeer` redirector stand-in *through* the proxy, and the
node's own `/metrics` is the assertion oracle. `ManagerPeer` (in
`test_cms_resilience.py`) was extended additively to record every frame code in
arrival order — recording the *order* is what lets a test prove LOGIN arrived
first and intact after the link chopped and reordered it.

Coverage: join through latency+jitter, LOGIN reassembly under segmentation and
reordering, heartbeats under sustained noise; outage by silence, by refusal, by
accept-then-close and by mid-stream sever, plus rejoin on heal; a corrupting,
oversized-framing (`0xFFFF` dlen), storming redirector; and a 200-connection
storm plus 150 connect/abort cycles that must leave the gauge at exactly 1.
Every test additionally asserts data-plane liveness and scans `error.log` for
`exited on signal`/`SIGSEGV`/`Assertion` — "the federation leg broke" must never
mean "the site stopped serving data".

**TRAP — `brix-fault-proxy`'s `block` is accept-then-close, not refuse.** The
accept loop closes the client immediately, so the node sees a *successful*
connect and no connect failure is counted. That cost one failing test before it
was understood. Both modes are now covered: `ImpairedLink.down()` kills the
proxy outright for a true `ECONNREFUSED`, and `block` got its own test, since an
overloaded `cmsd` really does behave that way.

**Also.** The default 30 s `pytest.ini` timeout cannot hold a test that
deliberately waits out a backoff window; the module carries
`pytest.mark.timeout(180)` (precedent: `test_chaos_mesh.py`).

Full design record: `docs/refactor/phase-98-cms-aaa-federation-join-under-noise.md`.
