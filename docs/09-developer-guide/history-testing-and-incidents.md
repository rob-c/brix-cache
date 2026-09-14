# Development History — Testing, Conformance, CI, and Production Incidents

**Date:** 2026-07-15
**Status:** Living historical record — synthesizes the test-harness evolution,
conformance-suite build-out, and production/load incidents from May–July 2026.
**Scope:** the pytest/xdist harness and its footguns, the differential
conformance program (stock-xrootd, WLCG x509, WLCG token, multiuser
permissions), chaos/reload/resilience testing, load/perf testing, the k8s test
lab, and postmortems for real bugs those efforts found. This is the incident
and decision record; canonical *how to run things* docs are
`docs/09-developer-guide/testing/README.md`, `docs/09-developer-guide/testing-infrastructure.md`,
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
| `pkill -f pytest` / `pkill -f run_suite` / `pkill -f nginx` kills your own shell (exit 144) | These patterns self-match the invoking shell/wrapper | Use exact-comm `pkill -9 -x nginx`/`-x xrootd`, or `pgrep ... \| grep -v $$`; use `python3 -m cmdscripts.operator_build brutal_teardown` as the canonical reaper (scans `/proc/*/cmdline`, and since 2026-08-17 owns only paths under **your** `TEST_ROOT` — see §10) |
| A resilience/fault-proxy or destructive test flakes when run inside the shared fleet | The shared fleet (11094-12126) is itself flaky to bring up and shares state with everything else | Resilience/fault-proxy/destructive suites must self-provision dedicated nginx+xrootd on a private high port block, own PKI/data dir — never call `start-all` for them |
| Every token **accept**-case fails while every **reject**-case passes (e.g. `test_wr_01/02/04_*_accept` red on webdav *and* s3, `test_wr_03_read_scope_denies_write` and all `*_reject` green) | Fleet **signing-key desync**, never a scope/authz code bug: `TokenForge` is minting with keys the servers no longer trust, so *all* tokens die at authN — reject-expecting tests then pass trivially. An interrupted `restart` (it boots ~76 servers and regenerates PKI, easily >2 min) leaves the dedicated instances (`/tmp/xrd-test/dedicated/webdav-token`, `s3-bearer`, …) holding stale keys, and can abort mid-PKI-regen so the main nginx `[emerg]`s on a missing `ca.key`/`hostcert.pem` | Do not chase it into `scopes.c`/`validate.c`. Re-run `restart` to completion in the background with a long timeout — it may need two passes (first wipes and regenerates PKI, second converges) — and confirm `/tmp/xrd-test/pki/{ca/ca.key,server/hostcert.pem,user/proxy.pem}` all exist before re-testing |
| A CI lane that boots the fleet reports **success** in seconds, having tested nothing (`asan: SKIP — sanitized fleet failed to boot on this runner`) | `start-all` aborted because a spec tagged `critical` **skipped** — `ref-anon` calls `pytest.skip("selected xrootd binary is unavailable: xrootd")` and no GitHub runner image ships stock XRootD. The launcher treated "not installed here" the same as "broken", and the lane script treats a boot failure as a missing prerequisite, so the two combined into a green check | Fixed 2026-08-09 (`_absorb_or_reraise`): `critical` is fatal on a real FAILURE only; a `pytest.skip` from any spec is absorbed and logged. When a lane's log says SKIP, read it as RED — no lane that skips its fleet is evidence of anything. Follow-on the same day: with `asan` now a *required* check, every one of its `return 0` skip paths routes through `asan.skip_or_fail()`, and `.github/workflows/asan.yml` sets `BRIX_CI_STRICT: "1"` so a missing prerequisite is RED on the lane while a laptop without a compiler still skips |
| A lane aborts before it starts with `ERROR: test path(s) do not exist; refusing to start managed servers: <a file that plainly exists>` | `conftest._validate_requested_paths()` resolved relative arguments against **rootdir**, not the invocation dir. The repo-root habit (`pytest tests/foo.py`) makes those look interchangeable; a caller with `cwd=tests` (`tools/ci/asan.py` drives `pytest test_sanitizer_smoke.py`) passes a name that only exists under the cwd, so the pre-flight check rejected a file pytest would have collected fine — UsageError, exit 4, no fleet, no sanitizer | Fixed 2026-08-09: resolve against `config.invocation_params.dir` (what pytest itself uses), rootdir only as the fallback for builds without it. Guard: `tests/test_conftest_path_validation.py` — including the negative that the fix did not widen the check into "try either base" |
| A conformance/harness test "fails" and it looks like a server bug | Historically, ~90% of the time the *test* carried a stale assumption, not the server | Always verify differentially against a real stock `xrootd`/`XrdCl` reference before touching `src/`; see the conformance section below |
| A test in YOUR lane fails on a dead connection (`RemoteDisconnected`, `Connection aborted`) while the instance was healthy seconds earlier; its `error.log` ends `signal 15 (SIGTERM) received from <pid>` where `<pid>` belongs to no process of your session | Another lane on the box reaped you. Three reapers decided ownership by a raw **substring** of the cmdline, so `/tmp/xrd` and `/tmp/xrd-test` owned every `/tmp/xrd-test-<suffix>` root anyone else was using — a "clean my lane" was a SIGTERM of all lanes | Fixed 2026-08-17: ownership is a **whole path** (`fleet_orphans.owns`), used by `find_orphans`/`kill_orphans`, `operator_build.brutal_teardown` and `run_suite_unprivileged`. Diagnosing it needs the log at the moment of failure — teardown wipes the prefix, so a transport error must carry `error.log` into its own assertion message |
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
self-evident from `docs/09-developer-guide/testing/README.md`:

- **`TEST_SKIP_SERVER_SETUP=1` skips more than server startup** — it skips
  `conftest._setup_session()` entirely, including `X509_CERT_DIR`/
  `X509_USER_PROXY` env export. Anonymous tests pass, GSI tests fail "No
  protocols left to try" unless those vars are exported manually from
  `tests/settings.py`'s CA_DIR/PROXY_STD.
- **A live suite run without `TEST_SKIP_SERVER_SETUP=1` starts the WHOLE fleet
  in that lane** — ~70 nginx masters plus the cms/hybrid meshes and the KDC —
  before the first test, which is how a four-file phase-115 run got killed for
  memory on 2026-09-07 next to two peer sessions. The light recipes: a
  `uses_lifecycle_harness` suite runs standalone under `TEST_SKIP_SERVER_SETUP=1`
  (it starts its own instances); a `registry_server("<name>")` suite needs only
  `manage_test_servers start-dedicated <name>` in the same `TEST_ROOT`, then
  `stop-all` for that lane when done.
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
`docs/09-developer-guide/testing/configs/REGISTRY_MIGRATION.md` § "Declaring Servers (collection gate)".
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

---

## 10. Lane ownership is a path, not a substring — the cross-lane SIGTERM (2026-08-17)

**Symptom.** A tranche-15 file (`test_audit15y_cvmfs_origin_policy.py`) failed in
roughly half of otherwise identical nine-file runs, always in the same class, and
always as a *transport* failure rather than a wrong answer:
`ConnectionError(RemoteDisconnected('Remote end closed connection without
response'))`. Re-running the file alone reproduced it. Nothing in the test's own
logic varied between the passing and failing runs.

**Why it took a while.** The evidence was being destroyed by the thing that
should have preserved it. A transport failure lands *before* any assertion about
content, so the test died without ever printing the instance's `error.log`, and
the function-scoped `lifecycle` fixture then stopped the instance and the next
test's `register()` wiped the prefix. The fix that cracked it was one line of
diagnostics: make `_fetch` catch `requests.RequestException` and re-raise an
`AssertionError` carrying `error.log`. (Ditto for the mock origin: its stdout now
goes to a file, and the "never listened" assertion names the port's actual
holders. A fixed ledger port that is silently occupied by someone else is
unreadable otherwise.)

With the log inlined the answer was immediate and unambiguous:

```
… [warn] xrootd-fill: event=retry key="…" attempt=8 … next_backoff_ms=8000
… [notice] 3966304#3966304: signal 15 (SIGTERM) received from 3966974, exiting
```

Not a crash — an **external SIGTERM**, from a pid belonging to no process of that
pytest session, 25 s into a healthy instance's life while the client was still
inside its 90 s timeout. (`ulimit -c` is 0 on this box, so "no coredumps" was
never evidence of "no crash"; the sender pid in nginx's own notice is.)

**Root cause.** Three separate reapers decided which processes a `TEST_ROOT`
owns by testing whether the root was a **substring** of the process cmdline:

| Site | Test |
|---|---|
| `fleet_orphans.find_orphans` (backs `kill_orphans`, the conftest reaper and the post-teardown orphan alarm) | `marker in cmd or marker in parent_cmd or marker in environ` |
| `cmdscripts/operator_build.brutal_teardown` | `"/tmp/xrd" in cmdline or "/tmp/hsproto" in cmdline or str(test_root) in cmdline` |
| `run_suite_unprivileged._reap_test_servers` | `any(m in cmdline for m in ("/tmp/xrd", "/tmp/hsproto", "/tmp/xrd-test"))` |

Every side lane on this box is the default root plus a suffix
(`/tmp/xrd-test-a15aa`, `/tmp/xrd-test-fast-final-zero-2026…`), so `/tmp/xrd`
and `/tmp/xrd-test` are literal substrings of all of them. A "clean my wedged
lane" — which `conftest_part2` itself tells the operator to run by name — was a
SIGTERM of *every* live fleet on the machine. The two CLI sites were the worse
pair: their shared markers ignored the `test_root` argument entirely, so the
throwaway `tmp_path` that `test_cmd_operator_build` passes specifically to keep
the live fleet safe did not, in fact, keep it safe.

This is the third time the same trap has been sprung here. `conftest_part2`'s
reaper docstring already renounced these markers in as many words — "they can
occur in a healthy parallel lane's argv and caused collision recovery in one lane
to SIGKILL another lane's live fleet" — and the substring test quietly
reintroduced the identical failure for any root that is a *prefix* of another.

**Fix.** One ownership rule, in one place: `fleet_orphans._owns()` counts a hit
only where the match is a whole path — the byte before it starts the path
(string start, or a shell/environ delimiter) and the byte after it ends the path
(delimiter or string end) or continues that same path with `/` (which is how
`-p <root>/registry/<name>` is owned by `<root>`). `owns()` exports it for the
two CLIs, which no longer name a shared marker at all. The lead-side check
matters as much as the tail: without it `/tmp/xrd-test` would own
`/var/tmp/xrd-test`.

**Tests** (`tests/test_fleet_teardown_orphans.py`, all four fail against the old
substring rule where they should):

* the positive half, so the boundary rule cannot be tightened until it breaks —
  an argv naming a path *under* the root, and an environment naming the root
  exactly, are both still owned (the second is the only route a python fleet
  helper such as a mock Stratum-1 origin has, since it puts no path in argv);
* the detector: a root that is a text prefix of a sibling lane's root owns
  nothing of that lane's, by argv or by inherited environment;
* the reap: a real `kill_orphans` with a genuinely owned process present (so the
  SIGTERM and SIGKILL passes actually execute) leaves the sibling lane alive and
  still reapable by its own root. Under the old rule this test reports the
  sibling dead with `exit=-15` — the same signal 15 the incident's `error.log`
  recorded, which is what closes the loop between the reproduction and the
  finding;
* a source guard pinning both CLIs to the shared rule, so no shared marker comes
  back as a kill criterion.

**Rules this leaves behind.**

1. Never decide "is this process mine?" with `in` on a path. Use
   `fleet_orphans.owns`.
2. Never name a shared prefix (`/tmp/xrd`, `/tmp/hsproto`, `/tmp`) as a reaping
   marker. Your `TEST_ROOT` is the only boundary.
3. A test whose failure mode is a dead connection must attach the server's
   `error.log` to the assertion itself. Teardown will have erased it by the time
   anyone reads the report, and "who sent the signal" is in that log and nowhere
   else.
4. **The rule survives the reaper (2026-09-07).** `fleet_orphans.owns` fixed the
   harness, not the habit. Closing the phase-116 lane by hand, I scanned `/proc`
   for any cmdline containing `/tmp/xrd-p116` or `test_phase116` and killed the
   one match — a single `kill`, not a `pkill -f`, and still wrong: the match was
   peer 25's *watcher* shell, whose whole job was waiting for that root to
   disappear, so it was guaranteed to contain the string. Anything watching your
   lane names your lane. Even a one-shot manual teardown decides ownership from
   `/proc/<pid>/cwd`, an fd under `TEST_ROOT`, or `environ`, never from the
   cmdline text.

## 11. Collection/init hyper-optimization — four costs that scale with the suite, not the run (2026-08-17)

**Goal.** Repeated invocations (a single file, a `--collect-only`, a short
selection) paid tens of seconds of initialization that had nothing to do with
the tests being run. Profiling (`cProfile` on collection, `-X importtime`,
standalone timing probes) found four independent costs; all four are fixed.

**Before/after.** Single-file `--collect-only`: 23.7 s → 2.6 s wall.
Full-suite collect (38,429 tests): 47 s wall / 40.7 s user (and it *errored*
on 19 `ImportPathMismatchError`s) → 19.1 s wall / 16.0 s user, zero errors.
Session stop-sweep overhead in real runs: ~15–25 s → ~0.15 s. Session crypto
artifact setup: 11.3 s → ~0.02 s on a warm snapshot.

**The four costs and their fixes.**

1. **Session hooks ran the full fleet lifecycle for `--collect-only`.**
   `pytest_sessionstart`/`pytest_sessionfinish` booted watchdogs, ran the
   conservation check, and — the expensive part — swept every registered spec
   through `stop()`, each probing its ports with a separate `ss -ltnp` spawn
   (~250 subprocesses/session). Both hooks now return immediately under
   `config.option.collectonly` (`conftest_part2.py` / `conftest_part5.py`).
   For real runs, `stop_registered` now takes **one** `ss -ltnp` survey
   (`lib_py.util.listening_port_pids`) and skips every spec that is provably
   quiescent — no declared port listening and no pidfile on disk
   (`_server_launcher_part2_mixina._quiescent`). One sweep is ~135 ms; the
   per-port probes were ~50–100 ms *each*. When `ss` is unavailable the
   survey returns `None` and every spec is visited exactly as before.

2. **`inspect.stack()` in `server_registry._caller_site()`.** `stack()`
   eagerly builds source context for *every* frame in the (deep) pytest stack
   — ~84 ms per call, × 126 fleet registrations ≈ 10 s per session. Replaced
   with a raw `currentframe()`/`f_back` walk (microseconds). Rule: never call
   `inspect.stack()` on a hot path; walk frames yourself.

3. **The server-declaration gate re-parsed 1,040 module ASTs every run** (and
   again in every xdist worker). `conftest_part3` now persists the per-module
   analysis (`fleet_declares.analyze_source` usage rows + autouse specs) in
   `config.cache` under `fleet_declares/analysis`, keyed by
   `[st_mtime_ns, st_size]`; only gw0 writes under xdist; corruption degrades
   to a full parse. Unit tests: `test_conftest_fleet_lifecycle.py`.

4. **A bare `pytest` from the repo root crawled `k8s-tests/remote-suite/tests`**,
   whose basenames shadow `tests/` modules → 19 `ImportPathMismatchError`s
   *after* ~25 s of wasted collection. `pytest.ini` now sets `testpaths =
   tests`; explicit path arguments are unaffected.

**Bonus: cross-session crypto-artifact snapshot (`fleet_prep`).** Every
session regenerated identical PKI + proxies + signing keys + JWKS + issued
JWTs (~11 s) because sessionfinish rmtree's TEST_ROOT — even though step 3's
own comment said "reuse across sessions". `fleet_prep.prepare()` now
snapshots the pristine post-generation `pki/` + `tokens/` trees *outside*
TEST_ROOT (`~/.cache/nginx-xrootd/fleet-prep/<lane-key>`, honoring
`XDG_CACHE_HOME`) and restores them on the next session (~0.02 s). It lives
under `~/.cache` and NOT under `tempfile.gettempdir()` deliberately, and the
first cut got this wrong twice over: the suite pins `TMPDIR=TEST_ROOT/tmp`
(`conftest_part3`), so under pytest a `gettempdir()`-based cache lands
*inside* the tree sessionfinish destroys — permanently cold in the exact
context it was built for — and even real `/tmp` gets scrubbed by concurrent
lanes' `/tmp/brix*` tidying on a shared dev box. Anything meant to persist
across sessions must live outside both TEST_ROOT and `gettempdir()`.
Safety envelope: keyed per resolved
TEST_ROOT (scitokens.cfg embeds absolute paths); invalidated by generator
source stamps, by a 4 h TTL (proxies live 12 h, JWTs 24 h — every restored
credential stays well inside its window), and by sentinel files so a
tolerated generator failure is never snapshotted; `BRIX_FLEET_PREP_CACHE=0`
opts out. Each session still starts from a wiped tree — the snapshot is the
pristine state, so clean-slate semantics are unchanged. Tests:
`tests/test_fleet_prep_cache.py` (round-trip, TTL/corruption fallback,
generator-change refusal, incomplete-generation refusal, disable knob).

**Known pre-existing wart (not a regression).** `rmtree(ignore_errors=True)`
at sessionfinish leaves `registry/xrdhttp/ca-public/` behind: that directory
is deliberately created 0555 with 0444 files, so the unlink fails silently.
Present in lanes predating any of this work. `fleet_prep._force_rmtree`
shows the chmod-then-retry pattern if anyone wants to close it.

## 12. The clean that wasn't — stale `BRIX_CVMFS_OBJS` survive `make -C client clean` (2026-08-17)

**Symptom.** After inserting `int no_fsync` mid-struct in
`shared/cache/cas_store.h` (phase-104 batched-publish durability), every
`brixMount cvmfs` FUSE mount deadlocked forever: single thread blocked in
`pthread_mutex_lock` inside `brix_cas_pack_has` ← `cvmfs_fetch_object` ←
`load_trust_and_catalog`, right after fetching `.cvmfspublished` and
`.cvmfswhitelist`. The mutex word contained ASCII path bytes. A
`make -C client clean && make` — the standard struct-ABI remedy — did NOT
cure it, which is what made this one worth a postmortem.

**Why clean didn't clean.** The cvmfs client core links
`BRIX_CVMFS_OBJS` — ~30 objects compiled *into the `../shared` tree*
(`shared/cvmfs/**/*.o`, `shared/cache/*.o`) by a client-Makefile static
pattern rule. The `clean` target only removed client-tree objects, so those
survived every "clean" rebuild with the OLD struct layout. Stale
`client.o`/`fetch.o` (old `cvmfs_client_t` offsets — everything after the
embedded `brix_cas_store_t` shifted 8 bytes) mixed with fresh TUs: the
fresh reader's `fetch.cache`/`pack` loads landed on the stale writer's
`catalog_tmp` path bytes. All writes in-bounds of the one big
`cvmfs_client_t` allocation → **valgrind reports zero errors** while the
"mutex" holds text. Two extra traps compounded it: (1) the objects are
`.SECONDARY`, so after hand-deleting the stale `.o`, `make` still declared
`bin/brixMount` up-to-date (newer than all sources) and relinked nothing —
the binary must be removed (or a source touched) to force the relink;
(2) `-MMD` dep files listed the header, but the `.d`s live next to the
`.o`s in `shared/` and were equally stale/ignored by the incremental flow
people actually run.

**Diagnosis path that worked** (after strace/gdb-attach dead ends —
yama blocks attach; run UNDER gdb and `kill -INT` the gdb): breakpoint on
`pthread_mutex_lock` printing `$rdi` + lock word each hit → last hit showed
`lock=0x45524744` (ASCII); valgrind clean ruled out wild writes; a
`sizeof/offsetof` probe compiled under both flag sets ruled out flag-driven
layout divergence; `find shared -name '*.o' ! -newer shared/cache/cas_store.h`
found 85 stale objects and named the real culprit in one line.

**Fix.** `client/Makefile` `clean` now also removes
`$(BRIX_CVMFS_OBJS)` and their `.d` files. Full remedy for any
shared-struct change remains: `make -C client clean && make -C client -j`
— and that is now sufficient. Verified: quickstart 14/14, ingest-image
11/11, ingest-oracle 4/4 on the canonical rebuild.

**Rule sharpened.** "Struct field change ⇒ clean rebuild" is necessary but
was not sufficient before the clean-target fix; the failure mode of a
half-stale link is NOT a crash but in-bounds garbage — deadlocks on
text-filled mutexes, pointers into path buffers — invisible to valgrind
and immune to "but I rebuilt clean". If a brix client binary misbehaves
impossibly after a shared-header layout change, audit for object files
OLDER than the header across every tree the link list reaches:
`find client shared -name '*.o' ! -newer <changed-header>`.

## 13. Two harness traps found while closing the TPC off-arm audit (2026-08-18)

Both surfaced while landing `tests/test_audit16v_tpc_off_arms.py` (audit
tranche 16, file 22). Neither is about that file; both are about state that
outlives a session.

**A poisoned per-lane prep snapshot is permanent.** `brix_suite/prep_steps.py`
snapshots a lane's freshly generated `pki/` + `tokens/` under
`~/.cache/nginx-xrootd/fleet-prep/<sha256(test_root,pki_dir)>` and restores it
on the next session for the same `TEST_ROOT`. Both the store and the restore
are gated on `_missing_sentinels()` — "one per tolerated generator" — but the
`fleet-artifacts` step (`tokenforge.py fleet-artifacts`, the multi-key JWKS and
the two-issuer `scitokens.cfg`) had no sentinel. An interrupted run leaves
`jwks_multi.json` written and `scitokens.cfg` not; that half-tree passed the
sentinel check, got snapshotted, and was restored on every later session, where
the fleet died at conf time with

    nginx: [emerg] brix_token_config: open <root>/tokens/scitokens.cfg:
    No such file or directory in <root>/registry/token-registry/conf/nginx.conf:20

on both start-all attempts, so 0 tests ran. Regenerating by hand cures the
tree and not the cache: the next session restores the same half-tree. Two
lanes (`/tmp/xrd-16v`, `/tmp/xrd-16w`) were wedged this way and every retry
reproduced it identically — the classic signature of cached state, not of load.
**Fixed** by adding `tokens/scitokens.cfg` to `_missing_sentinels`, which makes
the half-tree both unsnapshottable and unrestorable, with two new cases in
`tests/test_fleet_prep_cache.py` (a killed forge is never stored; a snapshot
that lost the file is refused on restore). Manual escape hatch if a lane is
already wedged: delete its cache directory, or run with
`BRIX_FLEET_PREP_CACHE=0` once.

**A raw-socket TPC pull cannot complete without the client's half of the
rendezvous.** Native TPC is two opens of the SOURCE: the initiating client's,
carrying `tpc.key`+`tpc.dst`, which registers the key
(`brix_tpc_key_register`, `src/protocols/root/read/open_tpc.c:165`), and the
destination's pull leg, carrying `tpc.key`+`tpc.org`, which consumes it. Any
suite that drives the destination directly over the wire — without xrdcp — must
do the first open itself or every pull is refused `TPC authorization missing or
expired` before any gate under test is reached. Keys are single-use (consume
zeroes the slot), so one key is worth one transfer. The registry is one
shared-memory table per worker (`src/tpc/engine/key_registry.c`), so the
registering open may go to any listener in the instance, not necessarily the one
the destination will pull from.

**Carried out of the same session, then fixed (2026-08-22).** On that tree
`test_tpc_pull_integrity.py::test_clean_pull_is_byte_exact` failed with
`[3019] TPC checksum verify: cannot compute adler32 on destination`, and the
server log named the symptom — `brix: adler32 read("<dst>") failed (9: Bad file
descriptor)`. The session's diagnosis blamed the VFS-writer rework
(`brix_vfs_writer_fd` returning `NGX_INVALID_FILE` for a driver-backed staged
object). Instrumenting the refusal to carry its own evidence
(`[fd=17 writer=0 errno=9]`) showed otherwise: there was **no writer at all** and
the fd was perfectly valid. EBADF from `read(2)` does not only mean "closed" — it
also means **"this fd is not open for reading."** A kXR_open that asks only to
write maps to plain `O_WRONLY` (`open_flags.h`), so `t->dst_fd` — the handle the
pull WROTE the bytes through — can never be the handle it READS them back
through. The gate had been fail-closed on every clean verified copy since it
landed.

`tpc_verify_dst_hex` (`src/tpc/outbound/source_verify.c`) now picks a handle that
can actually be read: with no writer session the bytes are already fsynced at
`dst_path`, so it takes a fresh confined `O_RDONLY` fd beneath the same
`root_canon` that `done.c` unlinks through; with a writer session the bytes are
still IN the session and not yet at `dst_path`, so `tpc_verify_dst_hex_writer`
prefers the session's kernel fd and falls back to `brix_checksum_hex_obj` on the
driver-bound object. Both arms of the original diagnosis are handled; only the
first one was the bug.

**The second lesson is about the suite.** `test_knob_on_corruption_refused_no_poison`
— the security-negative for this very gate — stayed **green** through the whole
outage, because it asserted only `returncode != 0`. "Cannot compute" is also a
non-zero exit, so the test passed while the digest comparison it exists to prove
never ran once. It now pins the *reason* (`"checksum mismatch" in stderr`), not
just the refusal. A refusal test that does not name the refusal is a test that
cannot tell the gate from its own breakage.

---

## 14. Whose lane is it? — reaping a live session's fleet (2026-08-19)

§10 is the same word from the other side. There, the reaper's ownership rule was
too *loose* — a substring match let `/tmp/xrd-test` SIGTERM a lane called
`/tmp/xrd-test-a15aa` — and the fix made the rule exact: whole path components,
plus the parent-argv rule that catches the nginx worker whose own command line
names no path. That rule is now proven against a live fleet by
`tests/test_ci_ts3_settings_live_lane.py`, and it held. This entry is about the
question one level up, which nothing in that machinery ever asked.

**What happened.** A gate run of mine was SIGTERMed at its timeout. Looking for
leftovers I found ~211 fleet processes, read the lane root `/tmp/xrd-16aa` off a
`ps` listing, and called `kill_orphans('/tmp/xrd-16aa')` — twice. Sixty to two
hundred and fifteen processes died. `/proc/1749562/environ` afterwards showed
`TEST_ROOT=/tmp/xrd-16aa` belonging to a **live** concurrent session running
`pytest test_audit16aa_webdav_redirect_arms.py -n 2 --dist loadgroup`, started
seven minutes earlier and still going. Its suite was cut off mid-run.

**Why the listing looked like mine.** Lane roots are derived from the test file
name — `test_audit16aa…` → `/tmp/xrd-16aa` — so a root carries no session
identity whatsoever. A fleet mid-run and a fleet someone abandoned present
identically in `ps`: same daemons, same paths, same ages. `find_orphans(root)`
answers "which processes belong to this root" and answers it exactly; it has
never answered "is this root mine", and neither had anything else. Every part of
the machinery worked. The boundary I handed it was wrong, and precision on the
wrong boundary is a precision weapon. This host habitually runs several sessions
at once, which is the *normal* condition here, not an unlucky one.

**The fix: read the declaration, not the listing.** A harness puts `TEST_ROOT`
into its own environment. `/proc/<pid>/environ` reports that for every live
process, and unlike a path in an argv it is a *claim* rather than a reference —
daemons reference the tree, only the harness declares it. `brix_suite.orphans`
grew, in `tests/brix_suite/orphans.py`:

* `lane_claimants(root)` — every live process declaring that root;
* `lane_harnesses(root)` — the subset that is a harness;
* `live_lanes()` — the whole host as `{root: [(pid, cmdline)]}`, which is the
  check to run *before* a reap, since it answers the question a per-root query
  cannot: not "who is in this lane" but "which lanes are anyone's";
* `kill_orphans(root, force=False)` — the default — raising `ForeignLaneError`
  naming the pids instead of killing them.

A harness reaping its own lane is exempt automatically: the claimant is the
caller or one of its ancestors (`_ancestry()` walks up only, so a child harness
a test spawns still blocks its parent). That exemption is why the single
production caller — conftest teardown — needed no change at all, and why
`test_fleet_teardown_orphans.py` stayed 8/8 **unmodified** with the gate on.

**Two narrowings, and the second failed its own test first.** `TEST_ROOT` is
inherited by every process a harness shell launches, so the default lane on this
host showed 22 live "claimants" that were a `CodeChecker analyze -j 20` fleet
working under `<root>/tmp/` — live in the lane, unharmed by its teardown, and
enough to block every routine reap. Hence only *harnesses* gate a reap. Then
harness-ness itself: the first cut asked `"pytest" in cmdline`, and every path
under pytest's own `tmp_path` begins `/tmp/pytest-of-<user>/`, so a substring
test reads the directory a process works in as the program it runs. It passed
the harness case and failed the passer-by case in the same test. Matching is now
per argv token's **basename**, which keeps both real spellings (`python -m
pytest` puts the marker in a token of its own; `-m cmdscripts.manage_test_servers`
has no separator for `basename` to strip) and stops reading working directories
as identities. The general rule both narrowings serve: **a gate that fires on
the routine case gets `force=True` pasted over it, and then it protects
nothing.**

**A side effect worth recording.** `test_ci_ts4_prep_and_declares.py` pinned
`orphans.py` as a *verbatim* move from its `_legacy` archive by set-equality of
definitions, so the fix could not land without failing it. The archive pins the
**move** — that nothing was lost or quietly rewritten on the way across — not the
module's future, and a module nobody may fix is not an asset. It now carries
`_ADDED_SINCE_MOVE` and `_CHANGED_SINCE_MOVE`: named entries with reasons rather
than a superset rule, so a lost archived definition still fails, an undeclared
addition fails, an unrecorded edit fails, and an entry that outlived the edit it
was written for fails as stale. One comparison helper serves both the real pin
and its own negative test, so no second caller can reimplement a looser one.

**Gate:** `tests/test_ci_lane_ownership_gate.py` (11 tests — declaration
visibility, harness-vs-passer-by, self-reap, host view; the refusal, the
deliberate `force=True` override, the dead owner who must not hold a lane
forever; and the negatives: prefix siblings, `TEST_ROOT=` empty, a lookalike
argv that declares nothing, and a directory named like a harness). Narrative in
the plan: `docs/refactor/testsuite-modernization-plan.md` §7, ask viii.

**Open, seen while verifying the above.** One run of
`test_ci_ts3_settings_live_lane.py` printed `collected 13 items` and then
`no tests ran in 241.08s`, with **exit status 0**, no `[conftest] complete
fleet stayed healthy` line, no skip, no error and no traceback. The immediate
re-run of the same command was 13/13 in 198.0s. The host was carrying a
concurrent `CodeChecker analyze -j 20` fleet at load average 13–21 at the time,
so the likeliest reading is that the session-start fleet boot in
`conftest_part5.pytest_collection_finish` did not complete and the run was
abandoned quietly — but that is a hypothesis, not a diagnosis: the output was
captured through `tail`, so whatever was printed between collection and the
summary is gone. It is recorded here because the *shape* is the *fails green*
class this tree keeps paying for — a suite that does nothing and reports
success — and because a green CI run with thirteen collected and zero executed
is indistinguishable from a real pass in any dashboard. Reproducing it wants a
full untruncated log and a loaded host; the fix, if it is one, is in a
pre-TS-4 conftest that TS-7 is the first phase allowed to touch.

**Measured 2026-09-07 — the fleet-boot hypothesis above is wrong.** Every way
this harness can abandon a session was reproduced against pytest 9.0.3 and
xdist 3.8.0 in a two-test scratch project, and none of them is silent or green:
the `pytest.UsageError` that `_start_all_resilient` raises after two failed
start-alls exits **4** and prints its own `ERROR: start-all failed twice` line;
the same error raised inside an xdist worker exits **3**; raised from the
controller's `pytest_xdist_node_collection_finished` it exits **4**;
`pytest.exit()` and `session.shouldstop` (the sentinel's mechanism) both exit
**2** behind a `!!!!` banner; a worker that dies silently after collecting is
respawned and its items are reported `FAILED`, exit **1**. A bound fleet port
therefore cannot produce the signature — it produces a loud red that names the
port.

The only construct that reproduces the signature exactly — `collected N items`,
`no tests ran`, **exit 0**, nothing else printed — is a `pytest_runtestloop`
implementation that returns `True` without dispatching anything. Nothing under
`tests/` implements that hook; xdist's own `DSession` does, and it returns
`True` whenever its loop reaches `session_finished` with nothing scheduled. The
search therefore moves off the conftest fleet boot and onto the controller's
`DSession.loop_once` / `session_finished` path. Still open: no reproduction of
that state yet — every deliberate way of killing workers reports loudly.

**Coda (2026-08-20) — a guard-only selection is still a fleet run.** Verifying
the CI guards locally reads as the cheapest thing in the suite: every row in
`tests/test_ci_guards.py` is a `subprocess.run` of a text scanner that never
opens a socket. It is not cheap, because the fleet fixture is session-scoped
and autouse — selecting only the guard modules still boots (or attaches to) the
whole fleet, and it is the *teardown* of that session, not the guard rows, that
owns `TEST_ROOT`. A guard sweep started while another session's lanes were
live therefore carried the §14 hazard in full while looking like a static
check. Two consequences worth keeping:

- Check the host for a second live session before starting *any* pytest
  invocation, including ones whose test bodies plainly need no servers.
- To verify the guards alone, skip pytest: read the `_FAST` list out of
  `tests/_test_ci_guards_helpers.py` and run each `tools/ci/<name>.py`
  directly. Same artifacts, same verdicts, no fleet, no `TEST_ROOT`, seconds
  instead of minutes. Use the pytest rows when what you are testing is the
  *harness* — the injected-tree negatives and the backlog-growth refusals,
  which have no command-line equivalent.

The same sweep is also how a red guard gets misattributed. Four of the guards
were red on the working tree that morning and none of the findings belonged to
the wave being verified: `check_complexity` and `check_duplication` named
`fd_table.c`, `s3/copy.c` and `module_acc_directives.c`, all three carrying a
concurrent session's uncommitted `brix_read_only` work, and one of
`check_doc_links`' entries pointed at that session's untracked
`read-only-root-gateway.md`. On a shared working tree a guard verdict is a
statement about the *tree*, not about your change; attribute each finding with
`git status`/`git diff` before touching a line of it, because "fixing" the
other session's half-written feature is the §14 incident in a different
costume.

## 15. Two ways a test reports green having asserted nothing (2026-08-19)

Both found in the same afternoon, in the TS-5 gate tier, and they are the same
failure wearing different clothes: a check that never ran, reported as a check
that passed. Neither is exotic and neither leaves a mark in the output — the
only tell is a number you have to already know is wrong.

### 15.1 A skip escapes `pytest.raises(Exception)` and becomes the test's result

`test_ci_ts5_cachemx_move.py` asserts that `_cachemx._require_binaries()` skips
with a message naming the path it could not find — the message that would have
been the entire visible symptom of an unfixed `__file__` hop. Written the
obvious way:

```python
with pytest.raises(Exception) as excinfo:
    cx._require_binaries()
assert bogus in str(excinfo.value)
```

the file reported `26 passed, 1 skipped`. `Skipped` derives from
**`BaseException`**, not `Exception`, precisely so that a `pytest.skip()` inside
a helper cannot be swallowed by a broad `except Exception` somewhere up the
stack. That is the right design, and it means `pytest.raises(Exception)` does
not catch it either: the skip propagated out of the `with` block, out of the
test, and became the *test's own outcome*. The assertion below it never
executed. A green `1 skipped` for a test whose entire purpose is to prove a skip
is indistinguishable, at a glance, from the environment-conditional skips the
same file legitimately has.

The fix is `pytest.raises(pytest.skip.Exception)`. The durable part is the
second line of defence added with it — a `ran = True` set immediately after the
`with` block and asserted afterwards, so if the body ever stops reaching its
assertions again it fails loudly instead of skipping quietly:

```python
    ran = False
    try:
        with pytest.raises(pytest.skip.Exception) as excinfo:
            cx._require_binaries()
        ran = True
    finally:
        cx.XRDCP = saved
    assert ran, "the skip was not caught here"
```

**Rule.** Any test that asserts a *skip* or a *fail* — `pytest.skip`,
`pytest.fail`, `pytest.xfail` — must name the outcome class, never `Exception`,
and should carry a reached-the-end flag. The same applies to `KeyboardInterrupt`
and `SystemExit` for the same reason: they are `BaseException` too.

### 15.2 A gate file is classified slow by its filename and deselected

Recorded in full under the TS-5 (mesh) row of the modernization plan's Appendix
E; summarised here because it belongs with §15.1. `conftest_part3`
`_SLOW_MODULE_HINTS` auto-marks a module `slow` when its *name* contains any of
thirty-odd substrings; `pytest.ini`'s PR gate runs `-m "not slow"`. A gate file
named `test_ci_ts5_mesh_move.py` matched `_mesh`, all forty of its tests were
deselected, and the gate set reported `310 passed` — correct arithmetic over the
tests that ran, and no line at all for the file that did not.

The classifier reads a filename as a workload. Its own comment argues that
over-inclusion is safe because the full suite covers everything, which is true
of a slow suite and false of a gate, whose entire job is to be the fast tier.
The immediate fix was the filename; the standing one is
`test_no_ci_gate_file_is_auto_marked_slow`, which reads the hint tuple out of
the conftest by AST rather than copying it, and self-catches on the name that
caused the incident so a hint tuple that quietly loses `_mesh` cannot leave the
check passing over a tree it no longer protects. Marking by something a file
*declares* rather than by what it is called is carried to TS-7.

**Rule.** Before adding a file to the gate tier, check its name against
`_SLOW_MODULE_HINTS`. `interop`, `conformance`, `_load`, `_e2e`, `hybrid`,
`fuse`, `topolog` and `_mesh` are all in there, and several are words a gate for
that cluster would naturally use.

### 15.3 The tuple element that is empty by contract (2026-08-23)

A third instance of the same failure, found in `tests/test_cli_hints.py`.
`run_pty` (brixtest `clients/pty.py`) forks the child onto a PTY, which hands
it **one** terminal fd serving as both stdout and stderr; the function
therefore returns `(rc, combined_pty_output, b"")` — the third element is
empty *by contract*, always. Eleven tests unpacked it as
`rc, _stdout, stderr = run_pty(...)` and asserted hint text against `stderr`.
The C hint code was correct (verified by a manual `pty.fork` run); the tests
were grepping a string that cannot ever contain anything. Positive assertions
failed loudly ("expected exactly 1 note line, got 0"), but the
absence-assertions — "no hint on this arm" — passed vacuously, green, proving
nothing. The fix rebinds to the second element; `run_pipe`, which returns real
`(rc, stdout, stderr)`, was left alone. When a helper multiplexes streams, the
elements it can no longer populate should not exist in its return shape — and
a test asserting *absence* against a value should first prove the value can be
non-empty on some arm.

## 16. A path-keyed allowlist and a file that moved (2026-08-19)

`tests/test_server_registry_lint.py` enforces a policy worth having: no test may
start nginx itself instead of going through the lifecycle registry. Three files
are permitted to, and they are named in `LAUNCH_BACKLOG`, a shrink-only
`frozenset` of **paths relative to `tests/`**. The lint fails two ways — a
launcher not in the set, and a set entry that no longer launches — which between
them make the allowlist ratchet in one direction only.

The TS-4 launcher move broke it, and nobody noticed for two weeks.

```
E   AssertionError: new direct nginx launch(es) — route through the registry:
E   ['brix_suite/_legacy/_server_launcher_part2_mixinc_flat.py',
E    'brix_suite/launcher/internals.py']
```

`INFRA_ALLOW` exempts `server_launcher.py` and `_server_launcher_part2_mixinc.py`
**by filename**. TS-4 moved that stack into `brix_suite.launcher`, where the body
that launches now lives in a file called `internals.py`, and froze its pre-move
copy at `brix_suite/_legacy/_server_launcher_part2_mixinc_flat.py`. Neither name
is in the exemption; neither path is in the backlog. Two offenders, from a move
whose whole point was that nothing about the code changed.

### 16.1 The archive convention collides with every content-scanning guard

The second offender is the more general problem. A `_legacy/*_flat.py` archive is
a **byte-identical copy** of a module, kept so a later reader can prove the move
was verbatim. It therefore inherits every textual property the original had — and
any guard that decides by scanning file content will see it as a second instance
of whatever it looks for, at a path no allowlist has ever heard of.

That is not specific to this guard. Any check of the form *"no file may contain
X, except these paths"* acquires a new false positive each time a module
containing X is archived. The archive is not a test, is imported by nothing, and
runs never — so the finding is always wrong, and always requires an edit to the
guard rather than to the archive.

**Rule.** A guard that scans file *content* and allowlists by *path* must exclude
`tests/brix_suite/_legacy/` outright. Archives are frozen copies; they cannot be
fixed, only exempted, and exempting them one at a time is a ratchet running
backwards.

### 16.2 What it cost the perf cluster

TS-5's perf cluster is four modules and should have been five.
`tests/_perf_netem_helpers.py` — the unprivileged high-BDP A/B harness that
builds a `veth` pair inside a user+network namespace — is the third
`LAUNCH_BACKLOG` entry. Moving it produces three failures at once:

| what the move creates | how the lint reads it |
|---|---|
| `brix_suite/perf/_perf_netem_helpers.py` | new direct launcher, not allowlisted |
| `brix_suite/_legacy/_perf_netem_helpers_flat.py` | new direct launcher, not allowlisted |
| `_perf_netem_helpers.py` (now a shim) | **stale** backlog entry — no longer launches |

All three are fixable only inside `test_server_registry_lint.py`, which NG1 holds
unmodified until TS-7. So the module stayed flat, and the cluster carries a test
(`test_moving_the_netem_harness_would_break_the_registry_lint`) that computes the
two relpaths a move would produce and asserts neither is allowlisted — so the
deferral is a decision with a proof attached rather than a module someone forgot.

Leaving it behind turned out to be safe for a reason worth writing down. That
module re-executes *itself* inside the namespace, and its `--measure` child does

```python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _perf_ab_helpers import measure_read_throughput
```

Its `dirname` is still `tests/`, so the child finds the §10.2 shim and resolves
through to `brix_suite.perf._perf_ab_helpers`. Had **both** moved, that same line
would have found `_perf_ab_helpers` as a sibling in the new directory — the
import would have succeeded — and failed one import later on `settings`, inside a
child whose non-zero exit `run_ab_over_bdp` converts to `{"available": False}`
and `test_perf_netem_bdp` converts to a **skip**, in a file that legitimately
skips on any host without podman. `netns_bdp_available()` returns True here, so
that was a live path and the skip would have been a lie about the host.

### 16.3 The second guard nothing in the loop was running

This is the same shape as the `_FAST` gap found the day before, where four TS
guards joined the pre-push set by glob while the hand-maintained fast list did
not follow. Here the guard was neither in the gate set nor in `_FAST`, so a move
programme that reruns its own gates on every cluster ran this one exactly never
— until a cluster happened to need to read `LAUNCH_BACKLOG` and ran the file to
see what was in it.

**Rule.** When a phase moves modules across the tree, the suites to re-run are
not only the ones that *import* what moved. Anything that decides by **path** —
allowlists, backlogs, inventories, coverage maps — is a consumer too, and its
input changed even though no import did.

---

## 17. One composed module, one namespace — what a mechanical burndown rebound (2026-08-22)

The repo-wide complexity contract (absolute CCN 15 for C, and the new five-metric
`tests/test_python_quality.py` for Python) was landed by decomposing every
over-limit function in the tree. Most of that work is a long expression hoisted
into a helper. The helpers were generated per FILE and numbered per file:
`_expression_1`, `_expression_2`, and so on.

`tests/split_continuation.py` composes a module from shards by compiling each
shard into the **parent's** globals. That is one namespace, not several. A `def`
in a shard therefore does not shadow the parent's function of the same name — it
**rebinds** it, for the whole module. And Python resolves a function body's
globals at *call* time, so the parent's own call sites, written and reviewed
against the parent's definition, start reaching the shard's.

Three composed units collided:

| unit | what the parent asked for | what it got | how it showed |
|---|---|---|---|
| `cmdscripts/c_auth_units` | `_expression_4(base, fixtures, objs)` | shard's `_expression_4(needed)` | `TypeError`, whole `deleg_gate` unit red |
| `cmdscripts/client_features` | `_expression_1(proc)` → combined stdout+stderr | shard's `_expression_1(failed)` → an exit code | **silent**: journal assertions compared substrings against an int |
| `cmdscripts/gsi_trust_live` | `_expression_1(proxy_make)` → a skip result | shard's `_expression_1(result)` → a parsed HTTP code | **silent**: the `make_proxy.py` failure path stopped skipping |

Two of the three were silent, which is why this became a guard rather than a
review note. The loud one is the lucky case.

### 17.1 Identical copies are the same defect, later

`c_auth_units` carried **four** duplicated names across the parent and one
shard. Three were byte-identical copies of the parent's helper — harmless the
day they were written, and indistinguishable from the fourth, which had drifted
to a different signature. There is no way to look at a duplicate-name warning
and tell the harmless ones from the bug without reading both bodies, which is
precisely the work a guard exists to stop a human doing. So the guard admits no
"the bodies match" exemption, and the fix deleted the copies rather than
renaming them: they were never meant to be separate functions.

### 17.2 Guard #12

`tools/ci/check_shard_name_collisions.py` parses the parent and every shard of
each exec-composed unit and fails on any top-level name bound twice — across
files or twice within one file. It reuses guard #10's shard resolver rather than
re-deriving one, so it already understands all thirteen local aliases of the
composition helper, the `load_numbered` inclusive-bounds spelling and
`operator_runtime.py`'s open-coded `exec(compile(...), globals())`. Scope is the
composed unit, so two unrelated modules may both define `_output`; only module
level counts, so a nested function or a method never collides.

41 composed units scan clean. `tests/test_ci_ts5_shard_name_collision_guard.py`
carries the success, error and security-negative arms, each against a scratch
tree passed with `--root` — proving a guard fires by damaging the live tree is
never acceptable.

**Rule.** A mechanical refactor that generates names must generate them per
*namespace*, not per file, and the namespace of an exec-composed shard is its
parent's. Generic generated names (`_expression_N`, `_guard_N`, `_helper_N`) are
the failure mode's raw material: they are numbered by an algorithm that cannot
see the other file, and they carry no meaning that would make the collision
obvious in review. Names that say what the function does are not a style
preference here — they are what makes a collision visible.

## 18. `--dist load` ignores every xdist group — the cachemx cascade (2026-08-23)

A `suite --pr` run produced ~113 failures/errors in the parallel phase:
~103 `ConnectionRefused` across the whole cachemx family, three cvmfs cold-tier
ERRORs, a metric-delta assertion off by exactly one (`5 == 4`), cmsd and nginx
segfaults, and the cluster-ds fleet instance on :10070 found dead. Every one of
those was collateral of a single latent harness bug.

Fixed-port test families (cachemx, cvmfs, admin-rl, …) serialize themselves
with `xdist_group` markers so that one module's fixture owns its server for the
module's lifetime. That only works under `--dist loadgroup`. Four of the six
suite lanes in `tests/cmdscripts/operator_runtime_part2.py` — `_suite_fast`,
`_suite_pr`, the nightly slow lane, and the nightly clients lane — passed
`--dist load`, under which xdist **ignores group markers entirely** and
free-schedules tests across workers. A module teardown then stops the nginx
another worker is mid-request against (the ConnectionRefused cascade), a
concurrent family perturbs a Prometheus counter another test is delta-asserting
(`5 == 4`), and enough concurrent open/close against one instance can kill it
outright (the segfaults and the dead :10070 instance). `_suite_full` and
`_suite_sample` already said `loadgroup`, which is why the full tier never
showed it; the bug sat dormant in the `load` lanes until the cachemx family —
new, large, fixed-port — landed in their selection.

Mechanics worth keeping: `LoadGroupScheduling._split_scope` groups **only** by
the `@group` suffix on the nodeid; it never reads markers itself. The marker
works because each xdist worker's `pytest_collection_modifyitems` (in
`xdist.remote`) rewrites `xdist_group` markers into nodeid suffixes before
scheduling — so marker-only grouping is fully honored under `loadgroup` (proven
with a synthetic test) and fully invisible under `load`. A test carrying
several groups gets them joined with `_` into one suffix.

**Rule.** Any lane that can collect fixed-port or fixture-owned-server families
must run `--dist loadgroup`. `--dist load` is only safe for a selection proven
free of grouped tests — and since selections drift as families are added, the
safe default for every lane in this suite is `loadgroup`. When a wide,
previously-green family goes uniformly `ConnectionRefused` under parallel run
but passes serially, check the dist mode before suspecting the servers.

## 19. Crash traces without cores — the preload tracer, a stale-binary trap, and the cvmfs `$cvmfs_class` worker-killer (2026-08-24)

Recurring fleet nginx segfaults could not be root-caused the normal way on the
WSL2 dev host: systemd-coredump's pipe fails, `sudo` wants a password, and
`ptrace_scope=1` blocks gdb from attaching to non-descendants. The workaround
that finally produced evidence is a ~60-line `LD_PRELOAD` shared object: a
constructor reads `SEGV_TRACE_DIR`, pre-warms `backtrace()` (its first call
lazily `dlopen`s libgcc — not safe inside a signal handler), installs
`SA_SIGINFO` handlers for SEGV/BUS/ABRT/ILL/FPE that write
`exe= pid= sig= si_addr= ip=` plus `backtrace_symbols_fd` to a per-pid trace
file, then re-raises with `SIG_DFL`. The fleet launcher builds child env as
`{**os.environ, **spec.env}`, so exporting the preload for the
`manage_test_servers` invocation alone instruments every fleet daemon. The
fleet nginx is non-PIE, so trace addresses are link vaddrs usable directly
with `addr2line -e`. The tracer lives at `tools/diag/segv_trace.c`; build with
`cc -shared -fPIC -O1 -o segv_trace.so tools/diag/segv_trace.c` and start the
fleet with `SEGV_TRACE_DIR=<dir> LD_PRELOAD=<path>/segv_trace.so python3 -m
cmdscripts.manage_test_servers restart`.

Two traps came with it:

- **Symbolize against the exact running binary.** The fleet runs a
  content-hashed snapshot (`/tmp/brix-nginx-session-*/nginx-<hash>`), not
  `objs/nginx`. Three early symbolizations done against a stale `objs/nginx`
  produced confident, plausible, entirely wrong attributions (an nginx
  variable-lookup helper, the URI parser, the upstream peer picker) that
  suggested one heap-corruption bug wandering through innocent code. Against
  the live snapshot the same addresses resolved to three *distinct real bugs*
  (the cvmfs one below, a still-open `writev_try_aio` heap fault, and an OCI
  token-path NULL deref fixed in the phase-104 lane).
- **Never leave the preload in the pytest env.** Test-spawned ASan binaries
  refuse to start when the tracer displaces the ASan runtime from the head of
  the initial library list ("ASan runtime does not come first"). Preload on
  the fleet-start env only; keep pytest invocations clean.

The bug the tracer caught: `shared/cvmfs/grammar/classify.h` grew a `DICT`
class (enum now CAS..DICT, REJECT last = 5), and the correct 6-entry name
table with a clamped index went into `handler_finalize.c` — but
`cvmfs_var_class` in `src/protocols/cvmfs/module.c` kept a stale 5-entry
`names[]` with a `cls > CVMFS_URL_REJECT` guard that happily passes `cls == 5`.
`names[5]` read the adjacent zeroed static, so `$cvmfs_class` evaluated to a
NULL data pointer and `strlen(NULL)` fired in the access-log phase during
`ngx_http_free_request` — killing the worker on **every rejected cvmfs URL**
in any config that logs `$cvmfs_class`. The crash is in the log phase, so the
offending request itself was already answered; the casualty is whatever
requests the recycled worker was carrying. **Rule:** a name table for a shared
enum either lives next to the enum (single source) or clamps its index like
`handler_finalize.c` does; a range guard written as `> LAST` instead of
`>= COUNT` is exactly how a grown enum walks off a stale table.

## 20. The slow tier ate the fleet again, and the revive path was dead — two self-inflicted wounds dressed as flaky tests (2026-08-24)

A 14-file serial verification batch (guards + crl + priv-esc + proxy + oci +
cluster families) failed identically twice — 10 failed / 50 errors, with
`FileNotFoundError: /tmp/xrd-test/pki/ca/ca.pem`, whole families skipping on
unreachable servers, and 124 of 127 fleet nginx processes dead by session end.
Both times a plausible external culprit was at hand (a concurrent session's
teardown; a peer session's overlapping lane runs) and both attributions were
wrong. Health-probe bisection (pki sentinel + registry count + fleet proc
count between pytest invocations) pinned it to `tests/test_ci_guards.py` run
**without** `-m "not slow"`: its slow tier drives `tools/ci/coverage.py`,
whose nested instrumented suite run *owns* the fleet lifecycle — stop-all plus
`rmtree(TEST_ROOT)` — and additionally leaves `/tmp/nginx-1.28.3` and
`client/` gcov-instrumented at `-O0`. This exact failure is already written up
in the agent guide (§ BUILD & TEST, recovery recipe included) and carried an
imperative memory since 2026-08-10; it was re-hit anyway because the fast red
signature (missing PKI, dead servers) pattern-matched so well to the known
*external* wipe hazards. **Rule:** before blaming another session for a wiped
tree, run the health-probe bisection — the wipe mechanism must be named and
verified, and "a concurrent session did it" is subject to the same standard as
any other environmental excuse.

The second wound explains why the damage lingered across runs:
`manage_test_servers start-dedicated` — the revive path used by the
manager-mode module finalizer to resurrect the deliberately-killed
`cluster-ds` — had been dead since the complexity-contract wave. The wave's
mechanical expression extraction moved `port and pids_on_port(int(port))` into
a module-level `_expression_2`, but `pids_on_port` was a *function-local*
import in the caller; the extracted expression NameError'd on every
invocation. Every consumer ran it under `subprocess.run(...,
capture_output=True)` with no returncode check, so the failure was silent and
`cluster-ds:10070` simply stayed down, tripping the fleet-conservation
health check at session end. Fix: the import moved into the extracted helper.
**Rules:** an extracted expression must not depend on names that only exist in
a caller's local scope (the same class of break as §17's namespace collision —
mechanical refactors change scoping, and only execution notices); and a
teardown-side revive that swallows output needs at least a returncode log,
because its failure mode is invisible by construction.

## 21. The PR-tier burndown to zero — five distinct transient mechanisms, none of them "load" (2026-08-24)

Two consecutive full PR-tier runs (15.5k tests, `-n ~12 --dist loadgroup` +
serial phase) went from 13 red to a fully-explained set. Every red decomposed
into one of five named mechanisms — none was left as "the host was busy":

**(a) TCP-readiness ≠ worker-ready** (`test_audit15z_disable_tokens`). The
lifecycle harness's `readiness="tcp"` passes when the MASTER binds the
listener; a worker answers requests only from its event loop, entered after
every `init_process` hook — the seccomp install and its NOTICE (deliberately
last, `src/core/config/process.c`) included. Reading the error log straight
after `lifecycle.start` races the worker's first write and *loses on a warm
back-to-back instance restart* (pass-alone / fail-in-class). Fix: a
`_worker_settled()` helper — one completed *login* (not a bare TCP connect;
the kernel SYN-ACKs without accept) deterministically proves init finished.

**(b) The missing-`xdist_group` defect class.** Under `--dist loadgroup`,
UNgrouped tests free-schedule; module/class-scoped fixtures instantiate PER
WORKER. Every fixture that owns a fixed-name resource then collides with its
twin on another worker: fixed ports (`test_rpm_mirror_dnf`, bind conflict),
fixed lifecycle spec names (`test_redirector_no_server`, teardown-rmtree
during the other worker's `nginx -t`; `test_fault_proxy_corruption`, re-seeded
`/big.bin` under the other worker's cached ref md5), fixed shared data files
with per-test create/unlink (`test_protocol_edge_cases` readv,
`test_privilege_escalation_d` use-after-close — teardown unlink mid-way through another
worker's open), and fixed-name re-uploads via `OpenFlags.DELETE | NEW`
(`test_readv` — the second worker's module fixture re-runs delete-recreate
and a per-test open lands in the unlink window, 3011 on a file that
"exists"). **Rule: any module/class whose fixtures register a fixed spec
name, bind a fixed port, or create/delete a fixed-name file in a shared data
root MUST carry an `xdist_group` marker.**

**(c) A shared-capacity observability table.** The dashboard state tests
watch ONE row of main's 512-slot SHM transfer table — shared with the whole
lane's traffic. A full table drops the alloc *silently into the event ring*
(`transfer_table.c`: "transfer proceeds untracked" — nothing in error.log),
so the row being polled for may never exist. Tests asserting idle-timing
state transitions of a shared-instance table belong in the serial phase.

**(d) mtime is not a witness.** `test_cred_mint`'s C cases asserted re-mint
via `st_mtime` inequality: second-granular, and this WSL2 host's clock steps
backwards (known open issue), so a rewrite can land in the same or an earlier
second. Replaced with the semantic witness — notAfter jumps from ~100s to
~3600s out. **Rule: assert the semantic effect (content, serial, notAfter),
never a timestamp delta, for "the file was rewritten".**

**(e) A perf A/B whose premise lever silently missed.** The netem BDP A/B
caps the baseline's `tcp_wmem` autotune ceiling with `sysctl … check=False`;
when that write misses, the baseline fills the pipe itself (27 MiB/s where
the 128 KiB window predicts ~4) and the ratio floor fails as a "magnitude
regression". The child already read back `wmem_effective` as ground truth but
didn't act on it — now a missed cap is an environment SKIP naming the
effective value, and the test's summary line prints it. **Rule: a perf A/B
must verify its environment lever actually engaged before comparing legs —
and a `check=False` on premise-establishing setup needs a read-back guard.**

Also fixed en route: the lizard-backed `test_complexity_limit` (~11 s
single-threaded, legitimately over the 30 s session default under lane load —
`timeout(300)`, same allowance as `test_ci_guards`), and the cachemx
rename-evict race (the `mv` beat the asynchronous cache insert past the fixed
1 s `settle()`; the test now waits on the on-disk cached copy — the same
ground truth its sibling PUT-over-cached test asserts).

The run-8 residue added three more entries, two of them recurrences of the
classes above:

**(b′) The fixture-importing module is a separate free-scheduling unit.**
`test_ssi_wire.py` and `test_ssi_cta.py` both carried
`xdist_group("lc-ssi-wire")`, but `test_ssi_async.py` — which *imports* the
same module-scoped `ssi_server` fixture (fixed spec name `lc-ssi-wire`) —
did not. Free-scheduled onto another worker, its fixture instantiation raced
the wire module's teardown of the same registry dir: `nginx -t` hit
`[emerg] open() …/logs/nginx.pid (No such file or directory)` on a directory
the other worker's stop had just removed. **Corollary to rule (b): the group
marker must follow the fixture, not the file — every module importing a
fixed-name-spec fixture needs the owning module's `xdist_group`.**

**(f) A test that asserts TCP segment boundaries.** `test_fault_proxy_mitm`'s
`_CapEcho` captured only the FIRST `recv()` blob per connection, and three
tests asserted injected-prefix-plus-payload inside that single blob. TCP
preserves order, not segmentation: the proxy writes the forged PROXY header
and the forwarded client payload separately, and a fast `recv` returns the
header alone (`first[0]` = `PROXY TCP4 9.9.9.9 …\r\n`, payload in the next
segment). The capture now accumulates each connection's full stream into one
per-connection buffer. **Rule: never assert what one `recv()` returns —
assert the accumulated stream.**

**(g) A hang whose evidence dies at teardown.** The serial-phase
`test_verified_fill_records_checksum_for_xrdckverify` hit rc=124 (xrdcp hung
past its 60 s window on a cold 8 MiB fill) once in run 8; the module passed
4/4 standalone immediately after, and the lifecycle teardown had already
wiped `registry/brix-verify-*` — nothing left to triage. Unresolved as a
mechanism; the module's `_xrdcp` timeout path now snapshots the verify
instances' error-log tails into the failure message while the instances
still exist. **Rule: a harness that tears down its servers must capture
their logs into the failure artifact at the moment of failure — a red whose
evidence is destroyed by its own cleanup can never graduate past
"transient".**

## 22. A broken-main event: what a "duplication burned to zero" commit reddened (2026-08-26)

`9ab5c3f5` ("the duplication backlog burned to zero") consolidated many
duplicated code blocks into shared helpers and reshaped one C descriptor
table. Every consolidation was behavior-preserving, but each left a *test*
that had pinned the OLD source shape. A full `--pr` run against that HEAD came
back 14 red in the parallel phase (the serial/source/guard phase stayed clean
at 590/0). The 14 decomposed into four named classes — only one was a real
code defect, and it was the guard, not a test.

**(a) The nested-helper / extracted-caller scope bug — a recurring class.**
Three separate reds (`test_phase24_mirror` earlier, `official_interop_lib_part2`'s
`_mirror`, `test_conf_fattr`'s `bare`) share one shape: a mechanical
"extract-expression-to-module-function" refactor lifted a *caller* to module
level while its little helper stayed **nested inside** the original function.
At runtime the extracted caller resolves the helper name in MODULE globals and
raises `NameError`. `test_conf_fattr` is the clearest: `_expression_2/_3`
(module-level, lines 7-15) call `bare()`, which was defined nested in
`test_bindings_multi_set_list_value_parity` — five parametrizations all
`NameError: bare`. **Fix pattern: lift the pure helper to module scope; it has
no closure state, so the move is free. Rule: when an extraction pulls a caller
out of a function, every name that caller uses must also live at module scope
— a nested def left behind is a latent `NameError` the def-time parse never
catches.**

**(b) Stale source-structure audits against a committed consolidation.** Four
reds (`audit16q` ×3, `audit16t` ×1) were `_source`/`_read` scans asserting the
pre-dedup C literally. `audit16q` pinned a hand-written per-directive setter
`brix_acc_http_set_<name>, 0, 0, NULL`; the dedup replaced all three acc on|off
directives with the shared `brix_acc_http_set_onoff, 0,
offsetof(brix_acc_http_t, <field>), NULL` (the offset carries what the name
used to). `audit16t` pinned the literal `"cmpread=0\n"`/`"cmpwrite=0\n"`; the
dedup merged the two emitters into `brix_qconfig_emit_cmp` spelling the
disabled form as `"%s=0\n"` + key. **Both wire behaviors are byte-identical**
(offsets verified against `module_commands.c`; the format string emits the same
bytes). The audits were updated to assert the NEW mechanism while preserving
each audit's verification *purpose* (each directive still arms its own field;
the disabled form is still `=0`). **Rule: an audit that pins source STRUCTURE,
not behavior, must be re-pointed the moment a deliberate refactor changes the
structure — verify the behavior is preserved, then track the new shape; do not
weaken the audit to a tautology.**

**(c) A ground-truth parser stranded by a table reshape.** The
`root_readonly_gateway_deep.py::qconfig_keys` parser regex
(`{ "key", brix_qconfig_emit_\w+, <digit> }`) matched ZERO rows after the
qconfig table went 3-column → 4-column — a fixed-response-line column was
inserted between key and emitter, and constant-line keys now carry `NULL` where
an emitter used to be. The test failed with "the C table names 0 kXR_Qconfig
keys, withheld: []". Fix: a non-greedy DOTALL regex
(`{ "key", .*?, <0|1> }`) that skips the two middle columns and reads key +
trailing `public_safe`; now extracts all 15 keys with `version`/`role`
withheld. **Rule: a test that derives its expectation by PARSING a C table is
correct only while the table's column shape holds — reshape the table, re-teach
the parser, in the same change.**

**(d) A non-hermetic geo test (`audit15y` ×2).** `test_*_answer_mode` /
`test_the_order_does_not_change` drove the cvmfs `rtt` geo policy with the real
Stratum-1 hostnames `cvmfs-stratum-one.cern.ch,cvmfs-s1bnl.opensciencegrid.org`
and asserted the order-preserving body `1,2`. `rtt` measures **real
TCP-connect RTT** to each listed server (`geo_answer.c`) and ranks
nearest-first, preserving input order only for servers it cannot reach. On a
network-isolated box both are unreachable → `1,2`; on an internet-connected box
the probe succeeds and BNL's S1 answers faster than CERN's → honest `2,1`,
reddening a test that only ever asserts `1,2`. Fix: RFC-6761 `.invalid`
hostnames (`s1-alpha.cvmfs.invalid,...`) — unresolvable everywhere, so every
server lands in the order-preserving "unreachable" bucket and the local answer
is a stable `1,2` on every host, while still exercising the full
parse→probe→rank path. **Rule: a test that drives a code path which measures
the real network must feed it unreachable inputs, or it asserts the test host's
topology, not the code.**

**(e) The one real defect was the guard, not a test.** `check_file_size` red:
`src/protocols/webdav/access.c` at 603 lines (cap 600) from the commit's own
OCI-auth addition — a genuine over-cap needing a file split (extract the
`webdav_vfs_ctx_build*` group at the file's tail). The remaining parallel reds
(`conf_pgio`, `conf_sequences_b`, `readv_security`) passed alone in isolation —
class (b)/(f) port contention from §21, no code change. **Meta-rule: a
"burned-to-zero duplication" commit's real risk is not the C — it is the tests
that encoded the duplication as their contract. Re-run every source-structure
audit and every C-table parser after a consolidation lands, and classify each
red as stale-contract vs real before touching code.**

## 23. The fast-tier burndown after the 5f5822004 rebase — attribution before fixes, and two genuinely lost tools (2026-09-02)

The first full `-m "not slow"` run after landing 5f5822004 (hyperopt rounds
5–12 + phase-107 C1–C9 + BriXTest 0.16, 455 files, rebased onto phase-106
W1/110) showed 178 F + 2 E. Every family was **attributed via git archaeology
first** (`git log -S`, `git show <sha>:<path>`, `git ls-tree`) and only then
fixed; the reds split four ways:

**(a) My own commit's file splits vs source-structure audits** — the §22
meta-rule replayed exactly. `vfs_dir.c`→`vfs_dir_iter.c`,
`registry.c`→`registry_slots.c`, the depth-0 `brix_vfs_driver_rmtree` call
→`vfs_unlink_many.c`, and the round-9 `fd_table.c`/`fd_table_bound.c` split
each invalidated path-pinned assertions (phase56 ×5, phase27 ×4, session_bind,
tree_depth_cap, aio_op_latency). One subtlety worth keeping: a split can turn
a literal `ngx_memzero(&x, sizeof(x))` into the pointer form
`ngx_memzero(p, sizeof(*p))` when the object moves behind a ctx pointer — a
count-the-literal audit must count both spellings. Unity-build unit TUs
(`tests/unit/test_sd_*_nearline.c`) red for the sibling reason: new calls in
the included `.c` (`sd_http_cred_gate`, `sd_remote_params_cred`, …) need
TU-local stubs, never extra link objects.

**(b) My own gate working as designed** — 16 audit16ah reds were phase-107
C2/W6 refusing `kXR_prepare`+`kXR_stage` on read-only fleet faces
(`kXR_fsReadOnly` before the path scan). Fix in the CONFIGS
(`brix_allow_write on;` per server block — it is srv-conf only), not the gate.
Recorded in the phase-107 doc at the C2 gate table.

**(c) Origin drift that CI didn't catch** — phase-110 (7e2aa0639) shipped
`brix_io_latency_seconds` + the deprecated `_usec` help rewrite +
`brix_cache_requests_total` WITHOUT updating the pinned help catalog
(`tests/brix_suite/cachemx/_cachemx_catalog_data.py` — the canonical module;
`tests/_cachemx_catalog_data.py` is a TS-5 shim). A peer session's
UNCOMMITTED `brix_vfs_domain_mutation_total` family was also live in the
shared working tree and fleet binary; its help text is now pinned too.

**(d) Two tools that never existed in git.** `tools/split_large_c.py` and
`tools/split_large_tests.py` were referenced by tracked tests since 08-11 but
were only ever untracked working-tree files — no commit anywhere contains
them (verified: `git log --all --follow`, ls-tree at three heads, stash
trees, filesystem find). Any fresh clone of origin/main had those 4 audits
broken-by-construction; they now `pytest.skip` when the file is absent.
**Rule: a tracked test that audits a tool pins that tool into the repo — the
commit adding the test must add the tool, and a "works on my checkout" audit
green proves nothing about origin.**

Process traps from the burndown itself: a `cd` into a subdirectory persisted
across shell calls and made relative-path greps of `src` return silent false
negatives (briefly "proving" a symbol existed nowhere) — **grep with absolute
paths during archaeology**; and a background pytest task's output file held
only the tail of the failure list — re-run the shortlist in the foreground
before concluding.

## 24. The fail-fast race hunt: one real race — an unpinned fixed-port lifecycle subject (2026-09-05)

The standing ask: drive the fast Python tier fail-fast (`-x`) ten times over,
halt on the first red, fix real defects, recompile, repeat — to shake out rare
races. Most halts were the harness, not the code. Three are worth keeping:
the canonical fast selection is `-m "(not slow and not serial) and not
suite_job"` — the `and not suite_job` clause the operator adds
(`cmdscripts/operator_runtime_part2.py`, `_suite_marker`) is MANDATORY, and
without it the lizard/duplication CI guards and the pblock live perf benchmark
run and halt `-x` on CPU noise the real fast tier never executes; a
26-day-stale `/tmp/x509up_u1000` that `test_shutdown_resume`'s xrdcp fell back
to under chaos-reconnect (clear any old `/tmp/x509up_u<uid>` before a hunt);
and `-n4` on a 20-thread host stalls shared-fleet HTTP past the 15 s cachemx
client timeout — `-n3` is the completable setting.

The first clean-config run (17,398 passed, 90% of the tier) then halted on a
genuine race:

**`test_rate_limit_s3.py::test_http_scope_limit_sheds_webdav_too` —
`ConnectionRefused` on the module's own WebDAV port.** The module's
`shared_limit_server` fixture is function-scoped and starts the ledger subject
`lc-p105-rl-s3`, which keeps its STABLE name and fixed ports (so every worker
shares one prefix, pidfile and listen set); the module declared no
`xdist_group`, so under `--dist loadgroup` its two tests went to two workers.
Both started the subject; the loser's nginx failed bind(), `_launch_nginx`
saw `_master_owns_prefix` and **silently adopted the winner's master**
(readiness passed against the winner's listener); the winner's test finished,
its `close()` killed the master through the shared pidfile, and the loser woke
from its 3 s refill sleep to a dead port. A second face of the same defect:
`nginx -t` `RegistryCommandFailure` when the other worker re-rendered the
shared prefix mid-check. Isolated `-n3` reproduction: 5 red in 6; after the
fix 0 in 6, all four tests on one worker.

Fix: the sibling pattern — `pytestmark = [uses_lifecycle_harness,
xdist_group("lc-p105-rl")]` with a comment naming the race. Of the 12 modules
that resolve ledger ports through `lifecycle_ports_for`, this was the only
ungrouped one.

Guard: rule 2 in `tests/test_suite_parallel_hygiene.py` — a lifecycle-ledger
subject started by MORE THAN ONE test of a module must be pinned (`xdist_group`
or `serial`), matched as `pytest.mark.<x>` in the AST. The first draft's text
search accepted a *comment* that mentioned xdist_group as a pin — the fix's
own comment would have satisfied it. The scan follows `reexport(globals(), …)`
so a split module whose pin lives in its helper (`test_cms_parity_wave`) is not
flagged — a plain-text census had exactly that blind spot. Whole-tree exposure
after the fix: zero; the eight gridftp/xrdcp modules that start one subject
from several tests are all `serial`, which the conftest pins.

The one other timing-dependent behaviour seen across the hunt is benign:
`test_audit15c`'s dead-token-endpoint pull can report the generic "TPC pull
failed" instead of "token exchange failed" under load; it fails closed
(`kXR_error`) either way — only the diagnostic message varies.

### 24.1 The parse-only path that skipped the frozen binary (run 4)

Run 4 halted at 3,479 passed on a pure `nginx -t` test
(`test_audit16g_pmark_flags_b`) with `PermissionError: [Errno 13]
… objs/nginx`. The log's mtime and the binary's mtime were seconds apart: the
sibling session's `make` was relinking `objs/nginx` at that instant, and the
linker's output is not executable until the link completes. This is the storm
class §19 already closed for servers — `freeze_nginx` copies the binary once
per session and every launcher spawn execs the frozen copy — but
`config_parse.nginx_t` still exec'd `settings.NGINX_BIN` directly, the one
remaining live-path exec in the suite. Fix: route it through
`brix_suite.nginx_tools._nginx_bin()` like the launcher. The other
`NGINX_BIN` references in tests are `os.access` skip-guards, not execs.

**Rules: a fixed-port lifecycle subject is a shared-prefix singleton — every
module that starts one from several tests pins them to one worker; a guard
that looks for a marker reads the AST, never the text; and nothing execs
`NGINX_BIN` directly — every exec goes through the frozen copy.**

### 24.2 The one-strike startup gate (run 15)

Run 15 never dispatched: `full-fleet startup is unstable; listener(s) went
down before test dispatch: cms-mesh:<a_mgr>`. The label is topology A's front
door — a **stock** `xrootd` 5.9.6 manager, not brix — and the gate
(`brix_suite/harness/sentinel.py::_require_fleet_startup_stability`) had
declared it dead on ONE failed 1 s connect out of a 5 s sweep.

What the isolation showed. Seven mesh starts alone (five on the live binary,
two on the HEAD-only A/B build) kept all 18 manager front doors up for 12 s
after `wait_managers_up`, so the death did not reproduce; the registry was
gone by then so the a-mgr log was not recoverable. The one deterministic fact
the hunt did establish is a **`cmsd` segfault on every mesh start**, ~8 s after
the managers listen (`dmesg`: `error 14`, `ip == fault address` — a jump to an
unmapped page inside a thread), identical on both binaries, so a stock
`cmsd` artefact rather than anything the brix data node sends; the managers
survive it. That crash lands squarely inside the 5 s stability window of a
fleet that has just booted 200+ daemons.

The fix is to the gate, not the mesh: a label a sweep reports down is
re-probed once with a 3 s budget (`_confirm_missing`) and the run halts only
if that probe fails too. A listener that is really gone refuses the second
probe immediately, so a true death still halts the run in the same second; a
single missed connect no longer discards a 35-minute run.

**Rule: a gate that fails a whole run on a liveness probe confirms the
negative — one missed connect under a start spike is a measurement, not a
death.**

### 24.3 The silent worker exit — a worker-side `UsageError` xdist cannot report (runs 24–26)

Run 24 died 138 s in with a controller `INTERNALERROR` from
`xdist/dsession.py:217` (`worker_workerfinished: assert not crashitem`): gw0
had finished its session with the first test of the `lc-cms-hostile` unit
still pending, an exit status that was neither 2 nor 3, `shouldfail` and
`shouldstop` unset, and not one line of output from the worker. Run 25
(execnet debug on, the controller under `strace -e trace=close,dup2,dup3`)
died at the same point with a different face — `OSError: cannot send to
<Channel id=3 closed>` from `worker_collectionfinish → schedule()` — and the
execnet trace showed two workers each sending exactly one message after their
collection and then a `CHANNEL_CLOSE_ERROR` carrying a 5,963-byte traceback: a
real exception escaping the worker's channel code, not a dead pipe. The first
draft of this section blamed a dead execnet receiver thread; that reading did
not survive run 25.

The mechanism is pytest's, and reproduces on demand: a two-worker smoke suite
whose conftest raises `pytest.UsageError` on gw0 from `pytest_collection_finish`
gives run 24's assertion verbatim. `wrap_session` catches every exception from
the session body except `UsageError`, which it re-raises after setting exit
status 4; its `finally` still runs `pytest_sessionfinish`, where xdist's worker
sends `workerfinished` with that status; the re-raised error then escapes the
channel exec as `CHANNEL_CLOSE_ERROR`, which nothing prints. On the controller
`worker_workerfinished` special-cases only exit 2 — any other status with a
unit already assigned trips the assertion (run 24), and a `schedule()` that
reaches the closed channel first fails on the send (run 25). The message is
lost twice over: xdist prints a remote error only on `errordown`, which this
path never reaches, and the worker's execnet debug file lands under `$TMPDIR`,
which the suite pins inside the lane the teardown wipes.

Run 26 ran with a hunt tracer (`-p rh_trace`, scratchpad only): worker-side
wrappers on `pytest_collection_finish` and `pytest_runtestloop` logging any
escaping exception, plus a controller patch of
`WorkerController.process_from_remote` logging every remote error and
`workerfinished` payload — to a file outside `$TMPDIR`. (Its first version
compared against a non-existent `ENDMARK` attribute, raised inside execnet's
receiver thread and manufactured exactly the channel death it was looking for;
a tracer on that thread must never raise.) It named the window rather than the
raiser: all three workers *returned normally* from `pytest_collection_finish`
(30 s inside it — the fleet wait) and reported exit 4 without ever entering
`pytest_runtestloop`. That is the `perform_collect` shape: an exception raised
in `pytest_collection_modifyitems` sits in flight while the `finally` runs
`pytest_collection_finish`, fleet wait included, and only then propagates. The
raiser was the suite's own server-declaration gate
(`_enforce_server_declarations`, run from `pytest_collection_modifyitems`),
refusing two tests in a peer session's uncommitted `test_phase115_ram_tier.py`
(written 00:43, between runs 23 and 24) that used the `ram-cache` server
without `@pytest.mark.registry_server`. `pytest --collect-only` without `-n`
printed the report and exit 4 in 16 s; under `-n` the controller never
collects, so only the workers meet the gate — and `--deselect`ing the module
could not help, because the gate runs before pytest's own deselection. Three
runs and their fleet boots went to an error whose text existed the whole time.

The fix is in the conftest. A worker whose `pytest_collection_modifyitems`
raises `UsageError` first publishes the message to
`REGISTRY_ROOT/.xdist-collection-error`, keyed by the xdist `testrunuid` so a
file left by an earlier session on the same `TEST_ROOT` is ignored; the
controller's `pytest_xdist_node_collection_finished` (already `tryfirst`, so it
runs before xdist schedules anything) re-raises that message as its own
`UsageError` before it boots the fleet; and a worker that finds its run's
marker skips the fleet wait. Pinned by three tests in
`test_conftest_fleet_lifecycle.py` and by an end-to-end run: `-n2
--first-percent 150` (the other `UsageError` raiser in the same hook) now
prints `ERROR: --first-percent must be greater than 0 and at most 100` and
exits 4 in under a minute with no server started, where before it was the
`assert not crashitem`. Seen in runs 24, 25 and 26 of the fail-fast series.

**Rule: an xdist `assert not crashitem` or `cannot send to <Channel closed>`
with no worker output is a worker-side `UsageError` raised at collection time
— `pytest --collect-only` without `-n` prints it, and the conftest now forwards
it to the controller.**

### 24.4 `nginx -t` binds — a positive parse test on port 1 (run 27)

Run 27 was the first to get past collection after 24.3 and halted at 46 %
(8,049 passed) on a new phase-115 config-parse test that rendered its front
with `PORT=1, UP_PORT=2` and asserted `nginx -t` returned 0. `-t` does not
stop at the parser: `ngx_init_cycle` opens every `listen` socket before it
reports "test is successful", so as an ordinary user with
`net.ipv4.ip_unprivileged_port_start = 1024` the syntax line is followed by
`bind() to 127.0.0.1:1 failed (13: Permission denied)` and exit 1. The
negative tests in the same file pass only because their parse error fires
before the bind. Deterministic (2/2 in isolation), foreign, and present in a
second phase-115 parse test the run had not reached. Fixed by the owning
session with `free_port()` for the rendered ports.

**Rule: a parse test that expects `nginx -t` to SUCCEED must render
unprivileged, free ports; `PORT=1` is only safe on the negative side, and
only when the expected error precedes the bind.**

### 24.5 A new `docs/refactor/*.md` written mid-run reddens every lane (run 28)

Run 28 halted at 45 % (7,876 passed) inside a phase-116 non-regression
wrapper that re-runs pinned static suites in a subprocess: the phase-111
register-integrity suite reported a refactor document that no §7 group
classified. The document was a phase-115 design spike created at 03:38 —
seventeen minutes after the run started — by a sibling session. Nothing was
wrong with the test or the register; the partition check reads the directory
at collection time of the subprocess, so a file that lands while any lane is
live reddens that lane, not only the writer's. The owner registered the file
within a minute and the direct suite (`pytest --noconftest -q -x
tests/test_phase111_register_integrity.py`, 0.2 s) names the culprit
outright.

**Rule: a live-tree partition guard is a foreign-edit detector — before
saving a new `docs/refactor/*.md` on a shared box, register it and run the
0.2 s guard; when a `-x` lane halts on one, check the file's mtime against
the run's start before looking for a race.**

### 24.6 A relink of the multicall client binary is `EACCES` for every CLI test (run 29)

Run 29 halted at 41 % (7,305 passed) with `PermissionError: [Errno 13]` on
`client/bin/brixoci`. That name is a symlink to the multicall `brixMount`,
and the whole `client/` tree was relinked by a sibling session at the same
second the test exec'd it. The linker writes its output without the execute
bit and sets it only at the end, so an `exec` inside that window is
`EACCES` — not `ETXTBSY`, which is what a rewrite of a running binary gives.
Every CLI-driving test (xrdcp, xrdfs, brixoci, brixcvmfs, brix-fault-proxy)
shares that one file, so a client relink during a run is a guaranteed halt
somewhere, and the test it lands on is arbitrary.

**Rule: on a `-x` halt with `Permission denied` or `Text file busy` on a
`client/bin/` path, compare the target's mtime with the failure time before
anything else; a match is a foreign build, and the suite's freeze protocol
covers `make` in `client/` as much as it covers the nginx relink.**

### 24.7 A halt that reproduces 6/6 in isolation is a defect, and the sleep next to it was a different race (run 30)

Run 30 halted at 48 % (8,518 passed) on the phase-115 CMS select/proxy
suite: a client whose idle session should have been re-pinned to a newly
selected data server got `kXR_error 4003` from the old one. The suite's
`_settle()` was a fixed `time.sleep(0.4)` covering two data-node logins on
one manager, which looked like the classic registration race. It was not:
the single test failed six times out of six on a quiet lane, and a
deterministic failure is never a race. The owner then found the cause in
the server: once a session is pinned, the root dispatcher short-circuits
every later opcode to the pinned upstream before the manager ever sees the
open, so the re-pin path is reachable only from the CMS wake path and never
from the client's own request. The suite was right and the implementation
was incomplete.

The sleep was still a latent race — under `-n3` load two logins are not
reliably processed in 400 ms — and it was replaced by a readiness signal:
the manager arms its ping timer only after `brix_srv_register`, so the first
frame it sends the scripted node proves the node is in the registry
(`_CmsNode.wait_ready`, pinned by `tests/test_cms_node_readiness.py`).

**Rule: before hunting a race behind a `-x` halt, run the single test alone
on a clean lane several times. Six identical failures is a defect for its
owner, and any fixed sleep found on the way is a separate finding that must
be replaced by a wait on the event it was guessing at, not widened.**

### 24.8 A fixture that imports from a continuation shard fails at setup, not at collection (run 33)

Run 33 halted at 52 % (9,289 passed — the furthest yet) with
`NameError: name '_have' is not defined` at the top of a `pki` fixture. The
fixture lives in `tests/_test_gsi_handshake_helpers_b.py`, a continuation
shard that `split_continuation.reexport` compiles into
`_test_gsi_handshake_helpers.py`'s globals; `_have` is defined only in that
parent. A new suite had written
`from _test_gsi_handshake_helpers_b import pki` — importing the shard as a
module, so every function in it bound the shard's own module dict, and the
first call raised. The isolation rule from §24.7 settled it in two runs: a
NameError is deterministic, not a race.

What made it worth a guard is the shape. The import succeeds, so
`--collect-only` is green; the failure waits for the first call, which under
a module-scoped fixture is one test in one worker, 9,000 tests into a run.
Guard #10 (`check_shard_entrypoints.py`) censuses the `load`, `load_numbered`
and inline-exec compositions but not `reexport` — the spelling ~300 test
modules use — and nothing anywhere forbade importing a shard directly. The
naive rule ("never import a composed shard") is wrong both ways: three suites
legitimately pull self-sufficient helpers out of `conftest_part2/3`, and the
two §10.2 `load_test_part*` shims import their moved shard only to hand it
their `sys.modules` name. Guard #13 (`tools/ci/check_shard_direct_imports.py`,
pinned by `tests/test_ci_shard_direct_import_guard.py`) therefore judges the
closure: what the importer takes from the shard must not reach, through the
shard's own definitions, a name the shard resolves at module scope but never
binds. `pki` reached six such names; `_gsi_nginx` from the same shard reaches
none and may be imported.

**Rule: a composed shard is not a module. Take names from the parent that
composes it. A guard for an import-time defect must judge what the import
reaches, not the file's name — and it must be cheap enough to run before the
launch, because the halt it prevents arrives an hour in.**

### 24.9 A lifecycle spec name is a ledger key, and the fleet was the first to check it (run 34)

Run 34 halted at 52 % (9,133 passed, 22 minutes in) with
`RuntimeError: lifecycle spec 'lc-p115-cms-space-mgr' has no fixed port` from
`LifecycleHarness.register`. A new CMS suite started its manager through
`_mgr(lifecycle, MGR, ...)` in `_test_cms_parity_wave_helpers.py`, whose
`name=` is the caller's second argument, and the name had no row on the
lifecycle ledger. Isolation reproduced it 1/1 — deterministic, not a race
(§24.7). Two sibling suites shared the gap, and a fourth name (`pbgm-gsi`, in
a root-only suite) had been latent since Phase 5 removed the dynamic-port
fallback: it would raise the moment anyone ran that suite as root.

The shape is Phase 5's. A spec's *name* is the key to its port, and the lookup
happens once — at the first start, in the fleet, at fixture setup.
`--collect-only` is green because a name is a string until the harness asks
the ledger about it. `test_fleet_ports.py` proves the ledger consistent with
itself; nothing proved the consumers consistent with the ledger, so the fleet
was the first place to find out, and the most expensive.

Guard #14 (`tools/ci/check_lifecycle_spec_ledger.py`, pinned by
`tests/test_ci_lifecycle_spec_ledger_guard.py`) judges statically what
`register` judges at runtime: every `NginxInstanceSpec` that reaches
`.start()`/`.register()` without `port=` must resolve through
`lifecycle_ports_for`. The first draft judged the wrong thing. It took every
wrapper's second argument as a name, and `test_audit15f_cluster_tuning.py`'s
`_mgr(lifecycle, reason, ...)` — name fixed inside — turned eight reason
strings into eight findings, while registry unit tests that build specs and
never start them added five more. The landed rule follows the data flow
instead: a wrapper is a function whose started spec takes `name=` from one of
its own parameters; callers are judged at that slot, positional or keyword,
through module-level constants, one wrapper feeding another; a name the guard
cannot read (an f-string, a call) is left alone rather than guessed. `port=`,
a spec never started and a start inside `pytest.raises` are not its business.
On the real tree it judges 518 names through 48 wrappers; its first run
reported exactly the four that were missing.

The same run showed §24.6 from the inside. A concurrent partial
`make -C client` had left `libbrix.a` newer than `client/bin/*`; fourteen
minutes in, the first of the 66 test files that run `make -C client` relinked
every binary while other workers were exec'ing them. `make -C client -q`
(exit 0 means nothing to do) joined the pre-flight next to the `-t` check.

**Rule: when a runtime lookup is keyed on a literal in the tests, a static
gate can perform the same lookup before launch — but it must judge the values
that reach the lookup, not every string in the same position. A guard that
guesses has false positives, and false positives are how a guard gets
deselected.**

Coda (run 35). The four rows landed and run 35 halted at 51 % (8,983 passed)
on the *next* static gate: `test_no_unpinned_fixed_port_lifecycle_subjects`
(§24, the rule from run 1) now saw `pbgm-gsi` on the ledger, counted six
starters in `test_pblock_group_multiuser.py`, and found no
`xdist_group`/`serial` mark. The module is `privileged`, which
`conftest_part3._needs_serial` folds into the serial group at collection —
a runtime pin the detector could not see, and one no other privileged module
had exposed because none of them starts a ledger subject. The detector now
mirrors the conftest (`RUNTIME_SERIAL_MARKS`), and a drift test reads
`_needs_serial` so a mark dropped there drops here. The pre-flight lesson is
the sharper one: a ledger change was accepted on the ledger's own suites and
the guard, not on every static gate that reads the ledger. The static gates
over the tests tree are one family; before a launch, run the family: the
`_FAST` guard scripts, the hygiene/fleet-ports/port-ladder/register/guard-test
modules, and a `--collect-only` of the tier under the run's own deselects. Two
things the family taught on its first flight (run 36's pre-flight). A guard
red is only a fail-fast halt if a *fast-tier* test runs it on the real tree —
`test_ci_guards.py::test_ci_guard_green` is `suite_job`, so a `_FAST` guard
red (here `check_client_flags_doc` on a phase-115 doc line naming an unbuilt
flag) is a CI red, not a run red; read the marker before deselecting. And
`test_all_fixed_bands_sit_below_the_ephemeral_port_floor` rebases its bands on
`TEST_PORT_START`: a side check at 40000 (chosen to stay clear of a live lane
at 20000) puts the top bands above the 32768 floor and reds for that reason
alone. Run the static family at the lane's own start, when the lane is free.

### 24.10 A static audit pins the tree it can see, and that tree includes everyone's uncommitted src (run 36)

Run 36 was the deepest fail-fast pass of the series (9,725 passed, 55 %,
23 min) and halted on
`test_audit15i_tier_macro_surface.py::test_the_generated_inventory_is_the_expected_size`:
`assert 24 == 23`. The audit pins the `BRIX_TIER_DIRECTIVES` inventory to the
byte — 23 tier suffixes, 26 generated names, and the exact literal/macro-only
split — and a peer's uncommitted phase-115 row (`cache_serve_while_filling`,
`src/core/config/tier_directives.h`, written the previous afternoon) had moved
all three. Not a race: 2 failed / 8 passed standalone, deterministic, and
*latent for nineteen hours* — the module schedules at about 55 % of the tier
and every run since the row landed had halted earlier, on something else. The
fix is the pin's owner's (counts, docstring numbers, the declared-too set),
routed with the assertion text.

The lesson is about the pre-flight, again. §24.9's family (guards, ledger
gates, collect-only) checks the *tests* tree; it cannot see a src change that
a static audit counts. The `requires_local_server` marker does not name the
fleet-free subset either (it marks tests that write to the server filesystem —
19,731 of the tier carry it, so `not requires_local_server` deselects almost
nothing). The subset that can fly before the fleet is the one no marker names:
modules that touch no port, socket, client binary or subprocess. A
collection-time classifier over module text (including every shard a module
re-exports) is the cheap approximation; its false-red rate on a no-fleet run
decides whether it earns a place in the pre-flight. Rule: **a peer's
uncommitted src is part of the tree the static audits pin; the audits that
read src/ must fly, without a fleet, before the fleet is paid for.**

### 24.11 A pin suite can hide inside another test, and a directive is not landed until a user can read about it (run 37)

Run 37 halted at 45 % (7,978 passed, 16 min) on
`test_phase116_recent_phases_nonregression.py::test_pin_suite_still_passes[test_release20_directive_surface.py]`.
The phase-116 non-regression module is a meta-test: it re-runs the pin
suites (the phase 107/108/111/112/113/114 closures, the release-2.0 directive
surface and, since 2026-09-07, its surface-pins sibling, the ladder-shape
audits) as `--noconftest` subprocesses so that a
collection error or a skip-as-pass in one cannot hide behind another. The
inner red was
`test_release20_directive_surface.py::test_every_registered_directive_is_documented_for_users`:
three directives from the same peer's uncommitted phase-115 rows
(`brix_cms_admin_socket`, `brix_tpc_outbound_renew_lead`,
`brix_tpc_outbound_renew_strict`) were registered in `src/` and present in
the generated `directives.md` table, but named in no prose anywhere under
`docs/`. Deterministic (35 passed / 1 failed standalone), not a race, the
owner's to write.

Two things the pre-flight learned. First, the fast-tier gate set is not the
union of `_FAST` and the modules that name a guard: a meta-test can carry a
whole pin suite that no marker, no guard script and no module name reveals,
so the pre-flight now runs the meta-test itself (eleven suites plus three
guards, about two minutes, no fleet). Second, the tree a pin reads is wider
than `src/` and `tests/`: this pin is a *docs/* pin, and the foreign-edit
detector's roots (src, client, shared, tests, tools/ci, docs/refactor) did not
include `docs/03-configuration`. Rule: **a new directive lands in three places
at once — the registry, the generated table, and a sentence a user can read —
and a pre-flight that only reads the first two will pay a fleet to discover
the third.**

**Coda (run 40).** The class returned in a third shape: run 40 halted at
48 % (8,623 passed) on
`test_phase115_cta_journal.py::TestJournalGrammarIsEnforced::test_without_unescaping_a_legal_path_comes_back_mangled`,
a gcc-and-run pin that builds a neutered copy of `cta_queue_unittest.c` and
expects a named check to fire. The defence fired; the peer's helper
extraction the same morning had renamed the variable the check names
(`nasty` → `req_path`), so the pin's needle was stale. Deterministic, the
owner's, fixed in minutes. The pre-flight now runs, fleet-less, every
fast-tier module that names a changed `src/` `client/` `shared/` source by
basename (for that morning's edits: seven modules, about fifteen seconds —
the owner's own blast-radius grep chose the same seven). Rule: **a changed
C source's pins are found by grepping its basename through the fast tier,
and they fly before the fleet is paid for.**

### 24.12 A halt's evidence lives in the lane, and the lane is the first thing cleaned (runs 38–39)

Run 38 never produced a result: a Claude Code harness restart at 11:12:20
took the detached (`setsid nohup … & disown`) pytest with it at 13 %. A run
that must outlive the operator's session needs a supervisor that is not the
session.

Run 39 halted at 32 % (5,923 passed, 11 min) on
`test_phase116_dns_cache_and_seam.py::test_dashboard_dns_snapshot_lists_targets`:
the first `GET /snapshot` after `lifecycle.start()` got a clean EOF
(`RemoteDisconnected`) from the phase-116 DNS instance at ports 21199/21200,
no response bytes at all. Thirty-three isolated reruns (plain, under four CPU
hogs, and with two concurrent `/snapshot` hammers at ~18k requests per run)
and the phase owner's thirty-two never reproduced it; the dashboard request
path has no accept-then-close route (a NULL builder answers 507, a send
failure 500), seccomp is opt-in and no fleet spec arms it, and the DNS
registry is mutated only on the event loop. The one artefact that could have
decided crash-vs-close — the instance's `logs/error.log`, where a
`worker process exited on signal` line or an abrupt exit would show — was
gone: the run script's cleanup removed the lane's `TEST_ROOT` before anyone
read it, and the `lifecycle` fixture's teardown had already removed the
prefix inside it. The halt is filed unresolved for lack of evidence, not for
lack of trying.

The §21(g) rule ("a harness that tears down its servers must capture their
logs into the failure artifact at the moment of failure") was written for the
CMS harness and never generalised. It is now generic:
`brix_suite/harness/fixtures.py` carries a `pytest_runtest_makereport`
hookwrapper (re-exported through `tests/conftest.py`) that, for a failed
`call` report whose item used the `lifecycle` fixture, appends the tail of
every started instance's `error.log` as a report section — the hook runs
before fixture teardown, so the prefixes still exist.
`LifecycleHarness.error_log_paths()` names them; `error_log_sections()` reads
at most the last 64 KiB of each, decodes leniently, and skips a missing or
unreadable log rather than turning one red into two
(`tests/test_lifecycle_failure_log_capture.py`, 9 tests). The run script's own
post-`EXIT` tar of `registry/*/logs/error.log` turned out to be worthless:
run 40's came back empty, because the suite's `pytest_sessionfinish` →
`_remove_test_root()` (`conftest_part5.py`) wipes the whole `TEST_ROOT`
before the script's next line runs. `TEST_REGISTRY_KEEP_LOGS=1` had been a
settings field since the registry refactor with no consumer; it now has one:
with the knob set, the wipe first moves every instance's `logs/` to
`<TEST_ROOT>.logs/<instance>/logs` (`brix_suite/harness/log_preserve.py`,
`tests/test_registry_keep_logs.py`, 4 tests), and the race-hunt lane runs
with it set.

Two self-inflicted repro artefacts are worth a line so nobody chases them
again: at base 40000 the "foreign fleet" holding 400xx was my own serial
reruns' conftest fleets overlapping (no `TEST_SKIP_SERVER_SETUP=1`); at base
33000 a `bind() 34202 EADDRINUSE` (1 of 3 runs) was the lane's own sink/stub
ephemeral picks landing on its fixed ports, because 33000 sits inside
`ip_local_port_range` (32768–60999). A lane base must keep its whole
18,774-port window below 32768 or above the ephemeral range. Rule: **never
clean a halted lane before its instance logs are in the artifact, and never
trust a halt whose lane is already gone — the log is the only witness to a
worker that died, and a repro that cannot see it is a repro of nothing.**

### 24.13 A config-time red is deterministic by construction (run 41)

Run 41 was the first lane whose evidence survived it: 391 instance log
directories moved to `<TEST_ROOT>.logs/` by the §24.12 consumer and tarred
into the artifact. It halted at 49 % (8,730 passed, 17 min) on a fixture
`ERROR` in `test_phase115_tpc_cred_renew.py` — all nine tests share the
`renewlab` fixture — whose source instance failed `nginx -t`:

```
nginx: [emerg] brix_token_clock_skew is capped at 300s (security clamp
against unit confusion); got 3600 in …/lc-p115-renew-src/conf/nginx.conf:33
```

The test was created that morning and asks for a 3,600 s skew so that one
token is accepted by the source and already expired to the destination's
`brix_token_peek_exp`. The [0,300] clamp in
`src/core/config/shared_conf_merge.h` is identical in `HEAD` and the working
tree, so no binary built from this tree has ever accepted the file's config:
the test had not been run against its own tree before it was left in it. The
construction survives the clamp unchanged — `STALE_TTL` is −60 s, inside a
300 s skew and past expiry — so the fix is the number, not the design; it
belongs to the phase owner and was handed over with the traceback.

Attribution took one grep, and that is the point. A red at `nginx -t` has no
timing in it: config parsing runs before any process, socket, or credential
exists, so it cannot be a race, a poisoned tree, or a foreign fleet, whatever
else the host was doing. A `-x` lane that halts there has paid seventeen
minutes to learn what a `nginx -t` against the rendered template would have
said in a second. Two consequences: the first 49 % of run 41 is a partial
pass, not a clean bill for the rest of the tier, and is reported as such;
and the lane deselects the file until the owner's fix lands, the same way as
the other twenty-three foreign deterministic reds, because a `-x` hunt for
rare races cannot afford to re-halt on a red that is neither rare nor a race.
Rule: **a fixture `ERROR` at config test is attributed from the emerg line,
never reproduced; and a new lifecycle test file is not in the tree until its
author has watched its own instances pass `nginx -t` on the binary the tree
builds.**


### 24.14 A hand evaluation of a shared tree is only as good as the mtimes captured in the same command (run 42 pre-flight)

The rhB42 pre-flight at 17:00 on 09-07 redded the composed ladder gates:
`test_port_ladder.py:73` "port 21274 is assigned to BOTH lifecycle-shared[1094]
and lifecycle-exclusive[0]" and `test_fleet_ports.py:287` "bands overlap".
Two lifecycle-shared rows had been added at 15:54 without re-summing the tail
file, so every offset from lifecycle-exclusive onward was two short. Three
sessions then evaluated the same tree and reached three answers:

- the author first denied the edit, then traced it to their own ledger rows and
  repacked `tests/port_ladder_offsets_tail.py` at 17:07:13 (PORT_COUNT 2391→2393);
- a second session, scanning during that write, read a TORN mix — the repacked
  lifecycle-exclusive and cmdscripts offsets next to the pre-repack interop
  offset — that looked internally contiguous, concluded "already fine", and asked
  for the repack to stop;
- this session had the assertion text of the composed gates, which cannot come
  from a shard read (importing `port_ladder_offsets.py` directly raises at its
  exec-composed tail and leaves pre-tail values), and re-ran the gates: 87/87 at
  17:09.

Rules that fell out of it, all three now applied by the pre-flight:

1. the gate is the verdict; a predicate evaluated by hand or by a direct shard
   import is evidence of nothing;
2. a value read from a file another session is writing is dated by the mtime
   captured in the same command, or it is not dated at all;
3. a pre-flight red is attributed from the assertion text and the owner's own
   ledger, and it is re-run — never argued down from a snapshot.

Two more things surfaced in the same pre-flight. `make -C client -q` was red
because a foreign run had relinked `client/libbrix.a` at 16:04:38 inside a lane
(no session claimed it; the twelve `client/bin/*` stayed at 10:24). With no
`.o` newer than the archive it is a link-only fix, which is what the pre-flight
now checks before anyone rebuilds. And `test_server_registry_lint.py`'s argv0
pattern matched a closed list of three spellings, so a module that named the
binary as `_nginx_bin()` or `_NGINX` was never READ by the launcher guard — a
guard's silence about a file it never opened is indistinguishable from a pass.
The owner widened the pattern and pinned both directions (three rows).

### 24.15 A signal mask is per thread, and the worker's reaper answers a signal the thread-pool caller never sees (run 42)

Run 42 halted at 50 % (8,952 passed, 18 min) on
`test_audit15c_tpc_token_exchange.py::test_dead_endpoint_fails_closed`: the
pull against a destination whose token-exchange endpoint is `127.0.0.1:1`
answered kXR_AuthFailed with the generic `TPC pull failed` where the test
pins `token exchange failed (curl exit 7)`. Five earlier lanes had passed it.
The lane's own logs (the §24.12 consumer) held the evidence in the dead
instance's error.log, four lines apart: curl's stderr `(7) Failed to connect
to 127.0.0.1 port 1`, then the WORKER logging `signal 17 (SIGCHLD) received
from 851102` and `unknown process 851102 exited with code 7`. nginx's
`ngx_process_get_status()` had reaped the exchange's curl child.

`brix_subprocess_capture()` blocked SIGCHLD with `sigprocmask()` around
fork+waitpid precisely to stop that. But the token exchange runs on the TPC
pull thread (an nginx thread-pool task), and a signal mask is a property of
a thread, not a process: a process-directed SIGCHLD is delivered to any
thread that has it unblocked, and the worker's main thread, parked in
`epoll_wait`, always does. Its handler ran `waitpid(-1, WNOHANG)`, took the
status, and the helper's own `waitpid(pid)` came back ECHILD — which the
retry loop `while (waitpid(...) < 0 && errno == EINTR)` did not distinguish
from success. `status` kept its initial 0, `WIFEXITED(0)` is true, and the
helper reported "curl exited 0 with an empty body". The exchange then failed
at the token parse, whose message stays in the log, and the client got the
generic text. Fail-closed, wrong diagnosis — and the same stolen status
would read a FAILED `oidc-token` as the successful fetch of an empty token.
The window is the interval between the child's exit and the pool thread's
return from its final `read()`: a standalone reproduction with a reaper
thread of nginx's shape lost 32 of 300 runs; the lane lost about one
exchange in six, and only the dead-endpoint test can tell exit 7 from 0.

Fix (`src/core/compat/subprocess.c`): the command now runs under the
double-forked reparented agent the tree already uses for external commands
(`xfer_spawn.c`, `xfer_mover_agent.c`, `lifecycle_broker.c`). The
intermediate exits at once; the agent — never nginx's child — forks the
command with its stdout on the capture pipe, waits for it, and relays the
raw wait status over a socketpair; the caller drains the pipe, then reads
the status, and a status it did not receive is a failure, never a 0. The
agent also drops every inherited descriptor except its result socket,
because a fork of a multithreaded process carries the other threads' pipe
ends and would have withheld a concurrent caller's EOF until its own
command finished. The only process the worker can still reap is the
intermediate, whose status nobody needs (an `unknown process N exited with
code 0` notice, not a lost result). Pinned by
`src/core/compat/subprocess_unittest.c` (300 runs under a hostile reaper
thread, every one must report exit 7; then no reapable child) driven by
`tests/test_subprocess_capture.py`, and by the audit15c test itself.

Two siblings keep the old shape with the same unchecked `waitpid()` —
`src/tpc/outbound/tpc_token.c` (oidc-agent, on the pull thread) and
`src/protocols/webdav/tpc_cred_oidc.c`. Their env-bearing exec (OIDC_SOCK; an
empty envp for the helper binary) does not fit the helper's signature, so
migrating them means an envp parameter first; until then a stolen status
can only mislabel a failed fetch, not admit a token the source never issued.
Rule: **blocking a signal around a fork protects the calling thread only; a
child whose exit status matters must not be a child of a process that has a
reaper, so run it under an agent and treat "no status" as failure.**

### 24.16 Eighty-five unlocked `make` calls over one shared tree (census, not a halt)

**Evidence.** The run 42 pre-flight (§24.14) found the client tree not
make-clean at 16:04:38: three fresh `.o`, a fresh `libbrix.a`, twelve untouched
binaries — the footprint a killed default-target `make -C client` leaves for the
next session. A census of the suite explained how such a make gets started
inside a test at all: 85 call sites in 77 modules ran
`subprocess.run(["make", "-C", CLIENT_DIR, …])` themselves (rebuild a FUSE
binary, relink a preload shim, `make -n -B` a dry-run, `make xrd` before an
xrdcp case), and not one of them held a lock. GNU make has no cross-process
lock of its own. Two xdist workers reaching two of those sites on a tree with
one stale object both compile it and both re-archive `libbrix.a`; the second
archive or link reads a half-written input, and the failure lands in whichever
test happened to link second — a red with no relation to what it tests.

**Why it never redded in 42 lanes.** Every lane refused to launch until
`make -C client -q` was clean (the pre-flight's tree gate), so every in-lane
make was a no-op that touched nothing; the race needs one stale object, and the
gate removed it before the lane began. That gate is a lane convenience, not a
property of the suite: a peer's edit landing mid-lane, or any run launched
without it, arms the race for every one of the 85 sites.

**Fix.** One door: `tests/brix_suite/client_build.py` exposes
`client_make(client_dir, *targets, **run_kwargs)`, the same argv under a
blocking `flock` on `/tmp/brix-client-make-<sha1(realpath)[:12]>.lock` — outside
the tree (a `make clean` must not unlink the inode everyone else is blocked on),
keyed by realpath (two spellings of the directory share one lock), in `/tmp`
rather than the lane's `TMPDIR` (two lanes on one tree is exactly the case).
The keyword arguments reach `subprocess.run` unchanged, so a non-zero exit and a
`TimeoutExpired` arrive as they did and the lock is released on every path. A
mechanical rewrite moved all 85 sites (the `-C` form and the `cwd=` form; flags
before `-C` preserved). `tests/test_client_make_serialized.py` pins it: two
callers of one tree trace `start,end,start,end` (success); a failing recipe's
exit code and stderr reach the caller, a timeout releases the lock (error); and
no module in the suite runs a bare `subprocess.run(["make"…` any more, with the
detector proven non-vacuous on a synthetic offender (security-negative, the one
that keeps the race closed).

Rule: **a build tool with no lock of its own must not be invoked from a test at
all except through a door that holds one — and the lock lives outside the tree
it protects.**

### 24.17 A hand-written stub list for a generated table (run 43)

Run 43 (binary 2415d36d, 23 deselects) halted at 56 % — 9,952 passed, the
deepest fail-fast lane yet — on
`tests/test_c_object_units.py::test_c_object_unit[vfs_caps]`:

```
/usr/bin/ld: objs/addon/backend/sd_registry.o: in function `brix_sd_driver_find':
src/fs/backend/sd_registry.c:77: undefined reference to `brix_sd_ram_driver'
```

Deterministic, not a race: the unit reproduced in isolation through the same
runner (`cmdscripts.c_object_units.run_one`), and no earlier lane in the
series had reached the C-object family since the `ram` row landed (runs 36
and 42 halted at 55 % and 50 %, just short of it).  A halt that only appears
past the previous best depth is the fail-fast loop working as intended: every
green prefix retires a band of the suite, and the next halt is the first red
in the band the loop had never seen.

**Cause.** `sd_registry.c` generates its driver table from the central row
list in `core/types/fs_list.h` (`BRIX_FS_DRIVER_LIST(BRIX_FS_ROW)`), so the
object references every BACKEND row's `brix_sd_<sym>_driver` struct.
`tests/c/test_vfs_caps.c` links only `sd_registry.o` and satisfied those
references with a *hand-written* list of six tentative definitions (posix,
block, pblock, mirage, ceph, cephfs_ro).  Phase 115's W4 added the `ram`
BACKEND row to the list; the table grew, the hand list did not.  Nothing
tied the two together, so the tree's own guards (config coverage, driver
conformance, the row-list census) all stayed green while the unit became
unlinkable.

**Fix.** The unit now expands the same row list for its stubs:

```c
#undef BRIX_HAVE_CEPH
#define BRIX_HAVE_CEPH 1          /* force both library gates on: a stub for a  */
#undef BRIX_HAVE_SQLITE           /* symbol nothing references is harmless, a  */
#define BRIX_HAVE_SQLITE 1        /* missing one is a link failure             */
#include "core/types/fs_list.h"
#define BRIX_FS_ROW_BACKEND(ID, sym, name)   const brix_sd_driver_t brix_sd_##sym##_driver;
#define BRIX_FS_ROW_ORIGIN(ID, sym, name)
#define BRIX_FS_ROW_DECORATOR(ID, sym, name)
#define BRIX_FS_ROW_NEARLINE(ID, sym, name)
BRIX_FS_DRIVER_LIST(BRIX_FS_ROW)
```

The gates are forced on because the configure passes `-DBRIX_HAVE_SQLITE=1`
(and `-DBRIX_HAVE_CEPH=1` where librados is present) on CFLAGS, which the
unit's own compile never sees; the previous hand list already stubbed ceph
unconditionally for the same reason.  `fs_list.h` is a pure macro header
that nothing on the unit's include path pulls in first, so the forced gates
reach only the row list.

**Pins** (`tests/test_c_object_units_stubs.py`, fleet-less, 0.45 s):
every spec that links `sd_registry.o` expands `BRIX_FS_DRIVER_LIST(BRIX_FS_ROW)`
and hand-lists no driver stub; the detector fires on the old shape; and every
`brix_sd_*_driver` that `nm -u sd_registry.o` reports is a BACKEND row of
`fs_list.h` (skips when the object is not built) — so a driver reached by the
registry outside the row list is named by the pin before the compile fails.

Rule: **a stub list for a generated table is generated from the same list.**
A test that hand-mirrors an X-macro expansion is a second copy of the truth
with no guard between the two, and it goes stale on the first row nobody
remembered it for.

### 24.18 A move-verification pin that outlived the move (run 44)

**Evidence.** rhB44 (binary 6b449683, 2026-09-07 19:29–19:54) halted at 10,220
passed on two reds in `tests/test_ci_ts4_catalogue_merge.py`:
`test_the_topic_split_lost_no_specs` (`127 == 126`) and
`test_the_move_was_verbatim_apart_from_three_named_deviations`
(`dedicated_specs` diverged from the `_legacy/` flat archive). A fleet-less run
of the module showed four reds, not two: the literal `126` lived in four probes
and `-x` had simply stopped after the first two workers reached it.

**Cause.** Phase-115 W4.2 added the `ram-cache` dedicated spec to
`tests/brix_suite/catalogue/dedicated.py` on 2026-09-06 23:12 — the first
content edit to any moved catalogue definition since the TS-4 merge landed on
08-18. The module pinned the catalogue's size at the move as a literal in four
places and byte-diffed the living package against the archive with a
hard-coded three-name deviation set. Both are correct the day a move lands and
wrong on the first legitimate edit after it; no lane had reached the module in
the eleven days between, so it read as a mid-lane edit until the mtimes said
otherwise (and a peer was wrongly told the halt was theirs for ten minutes).

**Fix.** One `SPECS_AT_THE_MOVE = 126` floor; every probe reads the live count
from `_all_specs()` and asserts partition identity (`sum(topics) == all`) plus
`all >= floor`, so a lost spec still reds and growth does not. The deviation
set became a module-level `DEVIATIONS` ledger with one comment per entry
(`dedicated_specs`, phase-115 W4.2, is the fourth); the test is renamed
`…apart_from_the_named_deviations` so the count never drifts into its name.
A new pin, `test_a_named_deviation_still_exists_on_both_sides`, closes the hole
the ledger opened: `package.get(name) != text` is also true when the name is
gone, so deleting `register_full_fleet` from the package would have stayed
green. It counts `from … import` bindings as present (`_TESTS_DIR` is an
import in the package, an assignment in the archive). Module 15/15 fleet-less,
quality gate green.

**Rule.** *A pin written to verify a move must say what happens after the
move.* Either it compares against a fossil with a growing, commented ledger of
post-move deviations (this file now), or it retires with the move. A literal
count of a living table is neither.

### 24.19 A calibrated absence that was a defect (run 45)

**Evidence.** Run 45 (binary e22a06a3) halted at 6% on
`tests/test_cachemx_exposition.py::test_unset_threshold_family_has_no_samples`:
`brix_cache_eviction_threshold_ratio{port="20662",auth="anon"} 0.999999` had
appeared. The pin's docstring said "a matrix with no eviction threshold
configured exports NO sample row". `tests/configs/nginx_lc_cachemx.conf` sets
`brix_cache_eviction_threshold 99.9999%` on every stream plane. The twin in
`tests/test_cachemx_trim_evict.py::test_eviction_threshold_gauge_absent` asserted
the same absence for an instance that sets the threshold to `0.99` explicitly,
and explained it as the gauge being "policy-engine-only — calibrated live".

**Cause.** Until 2.0 readiness F6 the metrics slot's `cache_enabled` was keyed
on `brix_cache on` alone, so a `brix_cache_store` tier (the 2.0 grammar, no flag)
was not counted as a cache and exported no per-server cache row of any family.
Both pins were written against that output and pinned the absence as a
property of the threshold. The F6 fix in
`src/protocols/root/connection/handler.c` (a composed tier is a cache) made the
row appear with exactly the configured value. The server was right; the pins
had fossilised a defect and dressed it in a rationale.

**Fix.** Both pins replaced by the truthful contract, verified live on
e22a06a3 (exposition + trim_evict 102/102): a stream plane that has accepted a
connection renders its configured trigger as ppm/1e6; every row lies inside
(0, 1) and equals the plane's ppm, never the 0.9 merge default; rows carry
exactly `{auth, port}` with the auth word from the fixed mode table; the evict
instance's single row is its `EVICT_THRESHOLD`, not the reaper's high
watermark; the cache directory path never appears in the exposition.

**Rule.** *"Calibrated live" is an observation, not a contract.* A pin that
asserts an absence must name the configuration that makes the thing absent
and check that the configuration is really in force (here: grep the template
the fixture renders). An absence that the config does not explain is a defect
being pinned; give it a docstring that says so, or fix the defect first.

### 24.20 A census that reddened on a foreign new file, and a VM that died mid-drain (run 46)

**Evidence.** Run 46 (binary e22a06a3, 26 deselects) halted at 20:58 on
2026-09-07 with 5,818 passed, on
`test_phase116_dns_cache_and_seam.py::test_every_tracked_c_file_is_scanned_or_is_test_code`.
The lane never printed its traceback: at 21:00 the WSL2 VM took its fifth
machine-check panic of the day (`Machine check: Processor context corrupt`,
CPU 11, bank 0) during the xdist drain, and rebooted at 23:53. No `EXIT=`
line, no lane-log tarball, every peer session restarted.

**Cause.** Reproduced without a lane: the census's one stray was
`contrib/checksum-plugins/brix_cks_fnv1a64.c`, a site checksum plugin a peer
tracked at 20:06 (before run 46 launched; runs 44 and 45 halted earlier in
the order). `contrib/` was outside the DNS-seam guard's `SCAN_DIRS`, and a
checksum plugin is a shared object the worker `dlopen()`s, so a resolver in
one would run inside the server process unseen. Not a race — the census did
exactly what amendment 15 built it for.

**Fix.** The guard walks `contrib/` (2,456 → 2,457 files, still green); the
suffix census names contrib's `.example`/`.json`/`.yml` non-source; three
pins (planted `getaddrinfo` under the plugin tree, bare `<netdb.h>` there,
live proof the shipped plugins are in the file set); phase-116 amendment 17.

**Rule.** A whole-repo census red on a file you did not write is still
yours to judge: the census asks "is this shipped code?", and the answer
belongs in the guard, not in a deselect.


### 24.21 A peer's tests-only repair that landed between collection and execution (run 47)

**Evidence.** Run 47 was the first lane on the merged binary 37b058b0
(2026-09-08 02:54: a phase-115 serve-offload window, a directive-registry
move, and the 2.0 `brix_frm_*` directive purge, relinked after two
pre-flight refusals showed the tree had drifted from e22a06a3). It launched
at 03:01:46 and halted at 03:10:02 with 5,319 passed (29%) on
`test_audit16ah_frm_hc_arms.py::TestTheQueuePathIsNeverOpened::test_no_queue_file_is_ever_created`:
`assert ['noctrl.q'] == []`. The same module, run alone on the same binary
from a private port base, was 66/66.

**Cause.** The directive purge made the worker create the frm journal on
its own, which turned two "the queue path is never created" pins into
fossils, and the module's registry fleet carried three `brix_frm on` blocks
with three queue paths that the new process-wide agreement check refuses.
The peer who owned the purge repaired the module and its conf tests-only at
03:04:56 and 03:05:23. The lane had collected the module at 03:01:46: pytest
imports test code once, at collection, while conf templates, golden files
and helpers are read when the test runs. The lane therefore executed the
old pin against the new conf. Not a race, and not the peer's fault: this
session had told peers that `tests/` edits were fine while a lane ran.

**Fix.** No repository change beyond the peer's repair. The pre-flight's
static gates gained `test_fleet_port_uniqueness.py` (the post-halt sweep found it red on
four phase-115 files that `bind((H, 0))`; that census reads every
`tests/*.py` at runtime and would have been the next halt).

**Rule.** The freeze a lane needs covers `tests/` as well as `src/`: a test
module a running lane has selected must not change between the lane's
collection and its execution, and neither may anything that module reads at
runtime. The window for a peer's tests-only repair is between one lane's
`EXIT=` post and the next lane's launch post.

### 24.22 A flat-file edit that left the package copy behind (run 48)

**Evidence.** Run 48 launched at 03:20:07 on the same binary 37b058b0 and
halted at 03:43:57 with 10,366 passed (57%, the deepest lane by count) on
`test_ci_ts4_launcher_and_deploy.py::test_every_moved_body_is_byte_identical[server_launcher_part3.py-harness.py]`.
The pin reported one function present in the flat file and absent from the
package module.

**Cause.** This session's own §24.12 change (2026-09-07 12:36) added
`error_log_paths()` to `tests/server_launcher_part3.py` so the suite's
failure-report hook can read every registered instance's `error.log` before
teardown removes it. The TS-4 move keeps the flat launcher files and
`tests/brix_suite/launcher/` byte-identical through that pin, and the method
went into the flat file only. Latent 15 h across ten lanes because the pin
lives at 57% of the fast tier and no lane before run 48 had reached it.
Runtime was never affected: the hook calls the method on the runtime class,
which is composed from the flat files, so every failure report since §24.12
carried its sections. Only the package copy diverged.

**Fix.** The method was ported verbatim into
`tests/brix_suite/launcher/harness.py`; the move pin, the capture tests, and
the duplication, quality, shim and shard guards are green. The pre-flight's
static gates gained `test_ci_ts4_launcher_and_deploy.py`.

**Rule.** After touching a TS-4 flat file, run
`test_ci_ts4_launcher_and_deploy.py` before launching a lane. The
pre-flight's changed-source pins key on `.c`/`.h` basenames and do not see a
Python move-pin; a static pin that a lane reaches late belongs in the
pre-flight's static gates, where it costs seconds instead of a 24-minute
lane.

### 24.23 An in-process import of the worker strips `tests/` from the importing interpreter (run 49)

**Evidence.** rhB49 (launched 03:59:20 on 2026-09-08, binary cf481268) halted at
04:23:14 at 58 % — 10,438 passed, the deepest lane to date — on
`tests/test_ci_ts5_clients_move.py::test_flat_spelling_is_the_package_object[_xrdcl_proxy_part2-brix_suite.clients.xrdcl]`
with `ModuleNotFoundError: No module named '_xrdcl_proxy_part2'`. Worker gw2 had
run `test_maintainability_tools.py` as its 100th module and the TS-5 pin as its
271st. The `tests/` directory mtime (03:51:44, before launch) rules out a
transient tree mutation; the ordered pair reproduces the error deterministically
at `-n0`, and either module alone or the reverse order is green.

**Cause.** `tests/test_maintainability_tools.py:358` did `import _xrdcl_worker`
in-process. The worker's prologue `_strip_shadow_paths()` removes every
`sys.path` entry carrying `XRootD/_SHADOW_MARKER` — which is `tests/` itself —
before importing the real bindings. From then on every *first* top-level import
from `tests/` in that xdist worker fails, while modules already cached keep
working: that is why 170 modules passed in between. `_xrdcl_proxy_part2` is
imported by nobody else, so the TS-5 pin — reached by a lane for the first time
ever — was the first fresh import to die. An order-dependent per-worker
pollution, not a race and not foreign.

**Fix.** The encoder test now runs its probe in the worker's own interpreter
(`xrdcl._worker_python()` child, JSON result), never importing the worker inside
pytest. `test_ci_ts5_clients_move.py` gained a census
(`_in_process_worker_imports`: AST, any depth, the worker's own hosts excluded)
pinning that no suite module imports the worker in-process — red on the pre-fix
tree at exactly `('test_maintainability_tools.py', 358)` — a self-test proving
the census sees a function-level import, and a child-process reproduction of the
failing direction (import the worker, then a fresh `tests/` import must raise
`ModuleNotFoundError`). That reproduction lives in a child interpreter on
purpose: run in-process it would poison whichever xdist worker drew it, i.e. it
would be a second instance of the very defect it guards. The pre-flight's
static gates gained the TS-5 pin.

**Rule.** The worker is reached only through a child process — never
`import _xrdcl_worker` or `brix_suite.clients.xrdcl.worker` inside pytest. A
`sys.path` pollution is a per-worker, order-dependent halt that lands on
whichever fresh import comes first, far from its cause; and a static pin that a
lane reaches only at 58 % belongs in the pre-flight, where it runs in seconds.

### 24.24 Attributing a peer's full tier from the lane: extraction closures, split fossils, a cross-worker vanish, and a catalogue a `# HELP` grep cannot see (between runs 49 and 50)

**Evidence.** The phase-115 owner's full tier (finished 05:31 on 2026-09-08,
binary cf481268, rc=1) left some forty reds. Every red in a module the `-x` lane
owns or would reach before run 50 was re-run alone at base 24000 on the same
binary (`validate50.log`: 27 failed / 1,130 passed before repair) and attributed
by mechanism. None was a server defect; seven test-side mechanisms, one of them
a real race.

**Findings.**
1. *Extraction closures* (`test_wlcg_token_conformance_runtime.py`,
   `test_cms_hostile_conformance_e.py`): a complexity-guard extraction hoisted a
   body that read enclosing names (`futures`, the executor, the probe; the
   `admitted` counter and its socket) into a module-level function, so the
   probe fan-out raised `NameError` and the admission counter never moved. The
   helpers now take that state as arguments and return the value.
2. *Split fossils, twice.* `_test_cvmfs_conformance_srv_http_helpers.py` ended
   with the `SINGLE_RANGES` parametrize decorator, which had come to decorate
   `_last_modified` instead of `test_single_range`. In `test_audit16i_…` the
   `_b` shard re-executes only the helpers file (`reexport`) and never the
   parent module's globals: first five support tables, then twelve more
   module-level helpers, raised `NameError` in the shard alone. Every
   module-level name a shard needs now lives in the helpers file; the parent is
   docstring + `reexport` + test classes.
3. *Unsequenced `errno`* (`test_preload_dir_stdio.py` driver):
   `printf("%d %d", dirfd(d), errno)` evaluates its arguments in an unspecified
   order, so the printed `errno` was pre- or post-call at the compiler's whim.
   `errno = 0; int fd = dirfd(d);` then print.
4. *Cross-worker vanish* (`test_xrootdfs_web_conn_reuse.py`, the one real race):
   list a shared export, then stat every entry; another xdist worker removed an
   entry in between and the stat raised `FileNotFoundError`. `_stat_surviving`
   counts the entries that still exist and skips only when every one vanished.
5. *Stale pins*: the IPv6 label-set pin lacked the `state` label the cache
   store's bytes gauge grew; the TS-5 verbatim-move pin had no room for
   post-move amendments (`_ensure_sssadmin`, `WlcgInstance`, `_release_stale`)
   and now carries a declared amendment ledger with a success, a reported
   undeclared change, and a stale-row-cannot-hide-a-revert negative; eleven
   phase-116 literals needed `net-literal-allow` markers within the literal's
   own lines.
6. *Catalogue drift* (`_cachemx_catalog_{data,schema}.py`,
   `test_cachemx_catalog.py`): 24 families and two HELP texts had moved.
   Two traps inside it. The five `brix_cluster_server_*` families emit HELP only
   while a data server is registered, so they belong in `CONDITIONAL` and
   `LABEL_KEYS` and must stay out of the exact-equality HELP and CATALOG maps.
   `brix_cms_locate_coalesced_total` is written by the table-driven
   `mw_emit_scalar`, which a grep for `# HELP` literals never sees: the live
   scrape is the oracle, the grep only a hint.
7. *Host geometry.* The 24000 validation ran while the peer's isolation run
   held base 12000; a base reserves B+1..B+18807, so 24000 sat inside it and
   both results were suspect until re-run. Then the F3 relink "launch" at
   10:38 never ran (the script lacked its execute bit and `nohup` refused it)
   and I reported it as launched; corrected with the F3 owner.

**Rule.** A peer's tier is attributed the same way a halt is: one module alone
on the same binary, then the mechanism. An extraction must carry its closure
as arguments; a shard sees only its helpers file; `errno` is read in its own
statement; a shared-export listing is stale the moment it returns; a catalogue
pin is checked against the scrape, not a grep; and nothing binds at any base
without a posted window, because every base overlaps every other.

## 25. A comment that ate a `deny` rule — the line-carrying placeholder class (2026-09-09)

Found while re-verifying release register row 1 on a freshly built binary: the
2.0 SSS validation template grew a comment explaining its own access-control
slot, and fifteen grammar tests in the file went red at `nginx -t` with
`unknown directive ")"` on line 3 — a line the template does not contain.

**The mechanism.** A `{PLACEHOLDER}` that opens its line in a
`tests/configs/*.conf` template carries a whole line: the caller supplies the
indentation, and for block slots the trailing newline. `#` comments are
interpolated like any other text, so a comment that names such a slot receives
the substituted value:

* *With* a trailing newline, the comment ends on the value's first line and
  nginx parses the leftover prose as a directive. Loud, immediate, and the
  error blames a line number that exists only after substitution — which is why
  the first read of the template found nothing.
* *Without* one, the entire substituted line is swallowed by the comment. The
  directive is simply gone and `nginx -t` reports `syntax is ok`. A subject
  whose only access control arrives through a `{DENY_LINES}` or `{SSS_LINES}`
  slot comes up open, and every test in the file passes.

The second half is the reason this is recorded as a class and not a typo: the
suite's own security negatives are the tests most likely to be written this way,
and the failure mode is a green run.

**The sweep.** The first rule tried — "the placeholder is alone on its stripped
line" — returned zero hits on the very template that had just failed, because
its shape is `{SSS_LINES}    }`: the slot closes a block on the same line. The
rule that holds is *line-leading* (`^[ \t]*\{NAME\}`), validated by dumping
every distinct tail that follows such a placeholder across the corpus. Scanning
all 647 templates then found **fourteen** instances across eleven files
(`nginx_audit16g_pmark.conf`, `nginx_audit16p_proxy_certs.conf`, the two
`nginx_cms_parity_*`, `nginx_gridftp_allo_ev.conf`,
`nginx_gridftp_gsiftp_ev_xrd.conf`, `nginx_lc_frm_exec_seccomp.conf`,
`nginx_worker_deescalate_root.conf`, `nginx_proxy_protocol_edges.conf`, and two
more deliberately not named here — they sit in
`tools/ci/template_refs_backlog.txt`, and a mention in this narrative would
count as a reference to the ratchet and shrink the backlog without anything
actually using them) — all latent, each one waiting for its slot to be filled
non-empty. Every comment was de-braced; the convention is that comments name a
slot **without** braces.

**The pin.** `tests/config_templates.py` gained
`line_carrying_placeholders()` and `comment_swallowed_placeholders()`;
`tests/test_config_template_hygiene.py` (4 tests) holds the corpus at zero
violations, checks the scanner names the line and the placeholder it would
swallow (and stays quiet on a brace-free mention, a mid-directive placeholder,
and `${request_time}`), and reproduces **both** halves through real `nginx -t`
runs — asserting for the silent half that the parse returns 0 and exactly one
`deny` line survives. `tests/config_parse.py::nginx_t_text` was split out of
`nginx_t()` so a test can parse hand-built config text.

**Rule.** A template comment describes a slot by name, never by placeholder.
An `nginx -t` that says `syntax is ok` proves the grammar parsed, not that the
directives you wrote are in the parse tree — when a test's whole premise is a
directive arriving through a slot, assert the directive is *active*, not that
the config loads.

## 26. Three defects behind one green scenario runner — `cvmfs_live` (2026-09-09)

Found while sweeping the last of the bash-fleet residue out of the harness. The
six `cmdscripts/cvmfs_live.py` scenarios ran green, and all three of the
following were true at the same time.

**Absolute ports.** Every scenario hard-coded its ports — `12871/12872`,
`12861/12862`, `12895/12896`, `12851-12853`, `12881-12883`, `12896-12898`.
Absolute ports ignore `TEST_PORT_START`, so two lanes on one host collide, and
the last two blocks *overlap each other* (`12896` is both `connection_reuse`'s
cache port and `keepalive`'s mock port) — harmless only because the module runs
its scenarios one at a time. All six now draw one three-port block from
`fleet_ports.cmdscript_ports("cvmfs_live", 3)` and reuse it in turn, which is
sound because every consumer runs under the `cmd-cvmfs_live` xdist group.

**An undrained response, and a keepalive check that stopped testing.** The
socket-reuse scenario issued 200 requests on one connection and read the status
of each without reading its **body**. `http.client` binds an unread response to
the connection and refuses the next `getresponse()` with `ResponseNotReady`, so
from request two onward the scenario was failing on a *client-side* protocol
error rather than on anything the server did. The assertion "this socket was
reused" could no longer fail for the reason it was written to detect. A
`_drain()` helper now reads each response to completion and returns its status.

**Reaping one port of a config that binds three.** `start_nginx` is told the
single port the caller polls for readiness, and the teardown reaper cleared only
that one. A generated config with several `server` blocks leaks squatters on the
rest, and the next start dies with `still could not bind()`. This was invisible
while every scenario owned distinct absolute ports and became immediate the
moment they shared a ladder block — the port fix *created* the exposure, which
is the ordinary shape of this class. `live_common.config_listen_ports()` now
parses every `listen` directive out of the generated config (one line may carry
a whole `server { listen ...; }`, so the directive cannot be anchored to the
start of a line; `unix:` sockets are skipped) and the runtime reaps all of them.

**The pins.** `tests/test_cmd_cvmfs_live.py` gained the scenario-set pin and an
unknown-scenario rejection, a monkeypatched failure that must not be reported
green, `test_drain_permits_a_second_request_on_one_socket` and
`test_undrained_response_breaks_the_socket` against a real stdlib keepalive
server — the second is the security-negative shape: it proves the failure mode
is still reachable, so a future refactor that drops the drain reddens instead of
silently un-testing the scenario — and `test_multi_listen_config_reaps_every_port`,
which asserts a three-`server` config yields all three ports in declaration
order.

**Rule.** A port literal in a harness module is a lane collision waiting for a
second lane; draw from the ladder. And a check that "the connection was reused"
is only a check while the connection is still usable — read the body.
