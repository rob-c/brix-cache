# BriXTest — Modernizing the Test Suite into a Generic Server/Client Test Framework

**Date:** 2026-08-17
**Author:** architecture planning session
**Current reconciliation (2026-09-03):** the standalone generic framework is
implemented at repository path `brixtest/` (the product name remains BriXTest),
with its own tests, docs and dependencies. Uppercase `BriXTest/` paths in the
preserved original design should be read as `brixtest/`. Repository adoption is
complete for ordinary pytest-owned nginx fixtures: Phase 81 records zero inline
runnable configs and only three explicitly isolated operator/namespace
launchers. The lifecycle-port ledger and full collection are green; preserved
TS6–TS9 prose is historical design sequencing, not missing core API.
**Status:** IMPLEMENTED / CLOSED (reconciled 2026-09-03) — the generic `brixtest` package now
exists ground-up under `brixtest/src/brixtest/` (35 modules, every file well
under the 600-line cap), deliberately **without tests** per OP direction; the
two contract kits in `brixtest/testing/` are the seed the first test wave grows
from. Same-day second wave: the **test-services layer** (§7.11, F16–F20 —
artifact catalog, service log views, per-test workspaces, uniform waiting,
deterministic payloads) is implemented under `brixtest/services/` and wired
through the `fleet` fixture, the `workspace` fixture, and the new
`artifacts`/`logs` CLI verbs; each service encodes a specific incident from the
grown suite's history (key desync, basetemp rotation race, clock-backwards
hosts, whole-log greps) as a design rule rather than a workaround. Same-day
third wave: the **run-intelligence layer** (§7.12, F21–F25 — per-test full
output capture, sqlite run store with OpenSearch bulk export, self-contained
HTML portal, dynamic per-test servers from a dedicated port block, and a
resource watch flagging crashes/leaks/CPU spikes with per-test attribution) is
implemented under `brixtest/results/`, `brixtest/fleet/dynamic.py` and
`brixtest/harness/resources.py`, wired through the pytest plugin and the new
`results`/`report`/`export`/`portal` CLI verbs, and verified by a real
end-to-end pytest session (static fleet + dynamic server + pass/fail/skip/
param tests → store rows, scoped log slices, attributed samples, report,
export, portal round-trip, quiescent stop). Fourth wave (same day):
**feature-complete against the §7.10 ledger** — every promised API now
exists (`InstanceSpec.to_dict`/`from_dict`, warn-only `Registry.validate`,
`owns` public + conservation report artifact, the F12 `StubServer` base with
`OriginStub`, F13 `strict_templates` wiring, spec-env template rendering with
the `BRIXTEST_LANE_ROOT`/`PORT_BASE`/`PORT_SPAN` lane triple) — and, at OP
direction superseding the earlier "no tests" instruction, a **project test
suite** under `brixtest/tests/` demonstrates and tests the public API
end-to-end: static fleet addressing, marked log views, artifact
catalog, workspaces, payloads, `wait_until`, a dynamic `OriginStub`, spec
round-trip + validation tiers, the kind-contract kit, and the procworker
RPC including error frames. The checked-in `configs/servers.json` and
`configs/clients.json` are contract C2 in miniature; `tests/conftest.py`
activates them through the uniform `brix` fixture. The suite runs green
back-to-back on kept and fresh lanes with a proven-quiescent fleet stop.
The full CLI surface was then driven verb-by-verb against that same
project (`--project brixtest` — plan/start/status/restart/stop with
quiescence, prep --explain, lane status, artifacts list/path incl. the
miss contract, logs, gate explain in both verdict shapes with exit
codes, results list/show, report, export, a live portal round-trip on
the lane's top port, run, and `--json`); the CLI's `_App` now mirrors
the plugin exactly (F1 `spec_validation` tiers + F13 `strict_templates`),
and `python -m brixtest` works uninstalled via `brixtest/__main__.py`.
A fifth drill-down pass then proved the seams no serial run exercises:
the F24 allocator now **bind-probes** every candidate port
(SO_REUSEADDR — the launched child's own semantics) because lane
blocks sit inside the host's `ip_local_port_range` and a LISTEN-only
scan cannot see an outbound socket whose *source* port landed on a
lane port, with a provably-stolen renumber-and-retry in `request()`
(`dynamic.port_stolen` event; reserving lane blocks via
`net.ipv4.ip_local_reserved_ports` is the recommended host hygiene);
the plugin boots under **pytest-xdist** from
`pytest_xdist_node_collection_finished` — the controller's only view
of the collected set, since its own `pytest_collection_finish` sees no
items — running the same prepare→gate→boot path a serial run takes,
with the gate's refusal shape intact under `-n 2` (two documented
xdist degradations: markers/params capture columns are empty, not
reconstructible from bare ids, and the mid-run sentinel-abort check in
`pytest_runtest_setup` runs only where tests run, while the sentinel
runs on the controller). The BriXTest suite is green serial and `-n 2`
under both Python 3.13 and 3.9; `pip install -e brixtest/` in a clean
venv yields a working `brixtest` entry point, driven against the
example adapter; and the F13/F1 tiers are proven end-to-end (strict →
`TemplateError` naming placeholder and template, warn → stderr finding
then proceed, refuse → exit 1 in the C1 shape).
A sixth, behavioral drill pass then made the watchdog machinery prove
itself and fixed three real bugs it surfaced: **(1)** crash detection
was dead code for non-daemonizing kinds — `process_pids` filtered dead
children with `poll()`, so a killed server vanished from the provider
before the detector's re-confirm could pass; the backend now keeps
dead children claimed until `stop()`, which in turn must withdraw the
claim *before* the first signal (fix 2) or a racing sweep reads a
deliberate release as a crash; **(2)** the sentinel watched the whole
catalogue instead of the booted set, declaring an unbooted fleet dead
under selective boot — `FleetSentinel.start(watch=…)` now takes the
booted names; **(3)** the stop path's kill loop used `os.kill(pid, 0)`
which succeeds for zombies, so stopping any backend child silently
burned the full `stop_timeout` — zombie-aware `/proc/<pid>/stat`
checking took the BriXTest suite from ~9.6 s (with the stall hidden in
teardown from day one) to **1.2 s**. The drills proved, live: all
three F25 detectors (crash finding with per-test attribution on a
SIGKILLed dynamic server; cpu-spike on a busy-loop kind; leak verdict
on an allocating session-scoped kind at `resources.stop()`), the
sentinel's mid-run abort with culprit attribution
(`fleet-died.json` naming the running test) plus conservation delta
and crash finding for the same death, typed `PortExhaustedError` on a
two-port block, multi-role port allocation, session-scoped dynamic
servers surviving across tests, `WorkerTimeout` without wedging the
runner, `LogWaitTimeout` naming the pattern, F9 orphan classification
and reap (owned in-lane listener reaped; out-of-lane listener refused
by name and untouched), and a valid `events.jsonl` stream across nine
event kinds.
A seventh pass closed the operator's eight-requirement ask (§7.13) —
four features already held (registered-only boot, crash detection,
xdist, local isolation) and four were built: the **test↔server map**
(`results/mapping.py`: declared rows off the F5 gate closure, observed
rows off the store, rendered as ASCII matrix, Mermaid graph, and an
HTML matrix in the report; CLI verb `map` with `--run`/`--mermaid`),
**per-test cpu/mem/lifetime capture** (`util/testprobe.py`: rusage
self+children CPU delta, `/proc/self/status` VmRSS delta, `ru_maxrss`
— measured in the process that ran the test and shipped to the
controller as flat `user_properties` pairs on the teardown report, the
one channel xdist forwards; store schema v2 adds the three columns
with a per-column idempotent migration), **per-server SVG resource
timelines** (`results/charts.py`: self-contained downsampled
sparklines off the sample series, no scripts or assets), and
**file-linear streaming under xdist** (`HarnessConfig.file_linear`
upgrades the default `--dist load` to `loadfile` scheduling via
`pytest_xdist_make_scheduler`; an explicit operator dist choice wins).
The pass also fixed two real bugs its own verification counting
surfaced: **(5)** the collector held a single "current" record, so
interleaved worker streams under `-n 2` silently dropped whichever
test another worker started over — 11 of 13 tests stored; open records
are now keyed by nodeid (one per worker is legitimately open at once);
**(6)** dynamic servers requested on an xdist worker were invisible to
the controller's collector — the worker now buffers the names and
ships them on the same teardown `user_properties` channel (names only;
worker-side dynamic log slices stay unsliced in the lane — a
documented degradation). The suite was 13 tests at that checkpoint (a three-stage
stream pipeline joined it) — green serial and `-n 2` on Python 3.13
and 3.9, per-test cost columns populated 13/13 in all four modes, and
the pass-6 behavioral drills re-run green against the new plugin.
`BriXTest/src/brix_suite/` is a documented stub populated by TS-1+.
The running suite under `tests/` is untouched. Where §9.1's sketch and the
as-built tree differ, the build followed §9.4's export table (the 1.0
authority): `errors.py` sits at the package root, `fleet/kinds.py` and
`fleet/probes.py` are their own modules, and `events.py` + `testing/` exist as
top-level members. Verified by byte-compile under Python 3.9 and 3.13 plus an
end-to-end smoke exercise (throwaway `httpd` kind → levelled parallel start →
idempotent restart → sentinel + conservation → stop with quiescence proof →
warm prep-snapshot restore → four-channel gate verdict → events JSONL → CLI
usage guard). Migration phases TS-0…TS-9 below remain gated and independently
landable.
**Naming (OP direction, 2026-08-17):** the generic framework is **BriXTest**
(Python import package `brixtest`); the nginx-xrootd-specific layer keeps the
working name `brix_suite` as BriXTest's first adapter. Final spellings are
settled against `check_brix_namespace.py` at TS-1 (§15).
**Scope:** the Python test suite under `tests/` (harness, fleet, helpers,
CLI, assets). The C sources under `src/`, `shared/`, `client/` and the tests'
*behavior* are explicitly out of scope.
**Companion doc (to be produced at TS-0):**
`docs/refactor/testsuite-surface-inventory.md` — the mechanical
export/import inventory this plan's shims are verified against.

---

## 1. Executive Summary

The `tests/` tree is a ~298k-LOC Python system that boots, monitors, and
reaps a 126-instance server fleet, mints real PKI/token/Kerberos
credentials, isolates concurrent runs into port-and-path lanes, and drives
thousands of protocol-level client↔server interactions — all layered on
top of pytest through a conftest constellation, a spec registry, and a
launcher. Functionally it is a test *framework* plus a test *suite*;
structurally it is a directory of flat scripts held together by
`PYTHONPATH=tests` and `exec`-based file shards.

This plan turns that implicit framework into an explicit, installable one:

- **BriXTest** (`BriXTest/src/brixtest/`) — a **generic** server/client
  test framework: instance specs and a registry, kind-profiled lifecycle
  management, dependency-ordered fleet orchestration, readiness probes,
  lane isolation with non-privileged ports, an artifact-preparation
  pipeline with snapshot caching, a declaration gate that boots only the
  servers a test run needs, fleet-stability watchdogs, and a pytest
  plugin exposing all of it as fixtures and hooks. BriXTest knows nothing
  about nginx or XRootD.
- **`brix_suite`** (same distribution) — the nginx-xrootd **adapter**:
  the 258-constant settings surface, the 126-spec catalogue, the
  nginx/xrootd/haproxy kind implementations, config-template rendering,
  the WLCG/GSI/KRB5 credential forges, protocol stub servers, and the
  suite-specific fixtures.
- **Every capability is specified, not just relocated.** §7.3 defines
  fifteen feature specifications (F1–F15), each in four fixed parts:
  the grown-today shape, the parity surface the migration lands
  (byte-identical behavior), the additive enhancements the designed
  shape makes cheap (separately gated, never mixed into migration
  commits), and named failure modes drawn from a single error taxonomy
  (§7.5). The specs are grounded in measured constants and APIs read
  off the code (worker formulas, probe deadlines, cache keys and
  rejection grounds, the worker wire protocol, the kind-dispatch
  sites), hung on a named instance lifecycle (§7.3) and a stated
  session timeline (§7.9), composed into one dependency structure with
  a worked second-consumer example (§7.7) and a before/after debugging
  narrative (§7.8), fronted by an enumerated public API (§9.4), held
  to CI performance budgets (§12 guard #9), and rolled out through an
  additive-feature gate ledger (§7.10) under which no addition changes
  a default behavior on the day it lands. The point of the plan
  is precisely the delta of §7.6: the same behavior, moved from an
  organically grown shape into designed, documented, versioned
  features.
- **Deployment is a seam, not an assumption.** The launcher mechanics
  become a `LocalBackend` (fork/exec, pidfiles, ports ≥ 1024, per-lane
  offsets — everything runs unprivileged, as today). The backend
  interface is designed so a future `K8sBackend` can map the same specs
  onto containerized servers and clients (Deployments/Services/ConfigMaps/
  Secrets), building on the existing `k8s-tests/` interop lab (§8).
- **Migration is shim-first and behavior-frozen.** No test file is
  touched before the optional TS-7 tail; every flat import keeps working
  through `sys.modules`-aliasing shims; every phase passes a standing
  acceptance gate (collect budget, real-fleet round trip, xdist smoke,
  conservation check, all guards).

Everything in this document is grounded in AST-level measurement of the
tree as of 2026-08-17 (§3, §5, Appendices C–D).

---

## 2. Why This Strategy Exists

The suite is one of the largest artifacts in the repository — **~298k LOC
of Python in `tests/` top-level alone** (1,019 test modules, 146
mechanically split `_test_*_helpers` shards, 88 infrastructure modules),
plus `lib_py/`, `lib/`, `cmdscripts/` (144 files), `resilience/`,
`cvmfs/`, `unit/`, and 541 config-template files in `configs/` (535
`.conf`). It is green, fast (post collection-optimization: 19.1 s
full-suite collect, 0.03 s warm artifact prep), and heavily guarded. The
strategy exists because the *structure* underneath that health has
specific, measured pathologies — and because the next 100k LOC of tests,
and any move toward containerized test environments, will be written
against whatever structure exists. The pathologies, with code-level
evidence (counts AST-measured 2026-08-17 unless noted):

### 2.1 No package, no distribution

There is no `pyproject.toml` or `setup.py` anywhere in the repository. The
suite is importable only because `pytest.ini` sets `pythonpath = tests` and
every recipe says `PYTHONPATH=tests`. `cmdscripts/` is a real package (it
has `__init__.py`) but is invocable as `python3 -m cmdscripts.…` **only when
the current directory is `tests/`** — the package's identity depends on the
shell's cwd. Nothing declares the suite's dependencies (`requirements*.txt`
at repo root are repo-wide, not suite-scoped), its supported Python versions
(3.9 is the known floor from the conda-env gotcha, 3.13.5 is the daily
driver), or its public surface.

### 2.2 A flat import namespace with generic names

88 infrastructure modules sit beside 1,165 test files in one directory and
are imported flat, with measured dependent counts:

| Flat import | Dependent modules in `tests/` |
|---|---|
| `settings` | **690** (40 of them infra-internal) |
| `server_registry` | **330** (19 infra-internal) |
| `split_continuation` (253 reexport + 10 load) | **263** |
| `lib_py.*` | 10 (but transitively load-bearing: the launcher imports `lib_py.util`) |

Names like `settings`, `util`, `config_parse`, `load_test` are one
`sys.path` accident away from shadowing something else — and the suite has
already lived a version of this failure twice: the 19
`ImportPathMismatchError`s from `k8s-tests/remote-suite/tests` basenames
shadowing `tests/` ones (fixed by `testpaths = tests`, 2026-08-17), and the
pytest rootdir-vs-cwd incident of 2026-08-09. The single-namespace
fragility that produced both remains.

### 2.3 Physical splits masquerading as architecture

The 600-LOC file-size guard was satisfied mechanically by
`split_continuation.load(namespace, anchor, *parts)`, which `exec`s
"part2…partN" shards into the parent module's namespace, and by
`reexport(namespace, module)`, which `exec`s a helper into a *test*
module's namespace. Measured split: **253 files use `reexport`**
(test-side; the most-shared shard,
`_test_cms_hostile_conformance_helpers`, is exec'd into 9 different test
modules — nine separate copies of its code objects at runtime) and
**10 use `load`** (the infrastructure shards — the TS-2/TS-4/TS-5
target). Concretely:

- `conftest.py:512-514` execs `conftest_part2.py` … `conftest_part5.py`
  into its own `globals()`. The five files share module state
  (`_pytest_config`, `_test_tree_wiped`) invisibly.
- `server_launcher.py` execs `server_launcher_part2.py` +
  `server_launcher_part3.py`; part2 assembles
  `class RegistryLauncher(_RegistryLauncherMixinA, _MixinB, _MixinC)` from
  three underscore-modules. Because each mixin file must also work when
  read standalone, **all three duplicate the same module-level helpers**
  (`_nginx_bin`, `_inject_nginx_load_modules`,
  `_inject_nginx_runtime_paths` appear at the top of `_mixina`, `_mixinb`,
  AND `_mixinc`) — triplicated code the duplication guard cannot see
  because each copy is "the" copy in its own file.
- `tokenforge.py` execs part2/part3; part2 assembles
  `class TokenForge(_TokenForgeMixinA…D, TokenIssuer)` from four mixin
  files. `x509forge.py` follows the same pattern.
- The fleet catalogue is sharded too: `fleet_specs.py:405` execs
  `fleet_specs_part2.py` into its own namespace. Part2 is **broken as a
  module**: `import fleet_specs_part2; fleet_specs_part2.ha_specs()`
  raises `NameError: name '_data' is not defined` (measured 2026-08-17) —
  `_data()` lives in `fleet_specs.py:46` and exists for part2 only under
  exec. Every shard file in the suite carries this latent property; the
  catalogue is simply where it is easiest to demonstrate.
- The exec pattern also hides a **circular import resolved only by exec
  timing**: `_server_launcher_part2_mixinb.py` does `import
  server_launcher`, while `server_launcher_part2.py` (which imports all
  three mixins) is itself exec'd into `server_launcher`'s namespace at
  the *end* of `server_launcher.py` — it works solely because
  `server_launcher` is already (partially) in `sys.modules` when the
  mixin import runs. An innocent reordering of `server_launcher.py`
  would break the launcher with no local diff to blame.
- IDEs, type checkers, coverage attribution, and plain grep-by-import
  cannot see any of these seams; the classes exist only at exec time.

### 2.4 Configuration is 580 lines of import-time module globals

`settings.py` exports **258 uppercase constants** (AST-counted: 178 port
constants, 39 roots/dirs, 41 other) — roots
(`TEST_ROOT`, `REGISTRY_ROOT`, `PKI_DIR`, `DATA_ROOT`, `TOKENS_DIR`,
`TMP_DIR`, `ARTIFACTS_DIR`, `CWD_DIR`), hosts (`HOST`, `HOST6`), registry
behavior knobs (`REGISTRY_ENABLED`, `REGISTRY_START`,
`REGISTRY_KEEP_LOGS`, `REGISTRY_STRICT_TEMPLATES`), binary paths
(`NGINX_BIN`, `ASAN_NGINX_BIN`, `BRIX_BIN`, `XRDFS_BIN`, `XRDCP_BIN`),
remote-mode detection (`REMOTE_SERVER`), and 178 fixed port
constants (`NGINX_ANON_PORT` = 11094 … the WebDAV/TPC/upstream ladders) —
every one computed from `os.environ` **at first import**. Lane isolation
(`TEST_ROOT` + `TEST_PORT_START`) works only because the environment is
correct *before anything imports settings*: an invisible ordering contract
that has produced real incidents (fleet key desync; the cross-lane SIGTERM
of history §10 was adjacent to the same lane-identity weakness). There is
no settings object to construct twice, inspect, validate, or diff, and no
way to unit-test lane math without `monkeypatch.setenv` + `importlib.reload`.

### 2.5 The harness lives in `conftest.py`, so it is untestable and unversionable

Session lifecycle — tree wipe, artifact prep, fleet boot, declaration gate,
stop sweep, orphan alarm, sentinel watchdog, conservation check, TMPDIR
pinning — is spread across `conftest.py` + four exec'd parts plus
`conftest_mu.py`. The harness unit tests (`test_conftest_fleet_lifecycle.py`)
cannot even `import conftest`: their own header comment warns that a bare
import resolves to the wrong module, so they load a **second copy by
path** via `importlib.util.spec_from_file_location("tests_conftest_under_test",
…)` — the only way to unit-test the harness today is to execute a
duplicate instance of it, the precise dual-identity pattern behind §2.2's
incidents, here institutionalized as test infrastructure. (Notably, *no*
test file does `from conftest import …` — the flat-import surface of the
conftest constellation is zero outside this by-path loader, which
simplifies TS-2 considerably.)

### 2.6 Two generations of fleet code coexist

The registry-native path (`server_registry` + `fleet_specs*` +
`RegistryLauncher` + `LifecycleHarness`) is the present.
`lib_py/dedicated.py` (bash-era `start_all_dedicated`, still calling
`regenerate_pki()` and hard-coding ports 11101/11102/11116/12120) and
pieces of `lib_py/nginx.py` are the past — still importable, still capable
of blitzing PKI out from under the modern path.

### 2.7 Assets have no owner

541 template files in `tests/configs/` (525 top-level + 10 `configs/mesh/`
+ 6 `configs/multiuser/`; 535 of them `.conf`), `fixtures/scitokens.cfg`,
`golden/`, two C probe sources in `helpers/`, `clientconf/` —
consumed by path arithmetic relative to `__file__` or `TEST_ROOT`, with
no manifest and no single loader. `check_template_refs.py` partially
guards the templates; nothing guards the rest.

### 2.8 The forcing functions

None of the above blocks day-to-day work. Three things make *now* the
time to act:

1. **Growth compounds structure.** Every new suite (each phase adds
   dozens of test files) hard-wires more imports into the flat namespace
   and more exec shards under the size guard.
2. **The harness has become a product.** §4 shows how much genuinely
   generic server/client test machinery already exists here; it is
   currently unusable outside this one directory and untestable inside
   it.
3. **Containerized environments are coming.** `k8s-tests/` already hosts
   an in-cluster interop suite and Helm charts; the local fleet and the
   k8s lab share *no* code today. A deployment seam designed now (§8) is
   cheap; retrofitting one under 1,165 test files later is not.

---

## 3. Baseline Metrics (2026-08-17, measured)

| Metric | Value |
|---|---|
| Python LOC in `tests/` top level | 297,740 |
| — of which test modules (`test_*`, `_test_*`) | 273,347 |
| — of which infrastructure (88 modules) | ~24,400 |
| Test modules / helper shards | 1,019 / 146 |
| Subpackages | `lib_py` (9 files), `cmdscripts` (144), `lib` (10), `resilience`, `cvmfs`, `unit`, `mu_authz_lib`, `perf`, `fuzz`, `userns`, `xo`, … |
| Config-template files (`tests/configs/`) | 541 (525 top + 10 mesh + 6 multiuser; 535 `.conf`) |
| Registered fleet specs / declared fixed ports | 126 / 127 |
| — fleet by builder | core 7 · xrootd backends 9 · support 10 · HA 3 · dedicated 97 |
| — fleet by kind | nginx 101 · xrootd 14 · proc 6 · external 3 · haproxy 1 · xrdhttp 1 |
| Test files importing fixed port constants | 414 (per catalogue docstring; re-measure at TS-0) |
| `settings.py` uppercase exports (AST-counted) | 258 = 178 ports + 39 roots/dirs + 41 other |
| Harness pinning suite (unit tests of the harness itself) | 67 test functions across 4 files (§5.10) |
| `split_continuation` split: `reexport` users / `load` users | 253 / 10 |
| Modules importing `settings` flat | 690 (40 of them infra-internal) |
| Modules importing `server_registry` | 330 (19 infra-internal) |
| Infra-internal in-degree hubs (AST-measured) | `settings` 40 · `server_registry` 19 · `server_launcher` 14 · `split_continuation` 9 · `cmdscripts` 7 · `config_templates` 7 · `port_ladder` 7 |
| Packaging files (`pyproject.toml`, `setup.py`) | 0 |
| CI guards whose code hard-codes `tests/` paths | 8 measured (§12) + in-suite source guards |
| Largest infra modules | `fleet_ports_shared_phase5.py` 1,120 · `conftest_part3.py` 609 · `settings.py` 580 · `conftest_part4.py` 536 |
| Full-suite collect (38,429 tests) | 19.1 s wall / 16.0 s user |
| Fleet artifact prep (warm snapshot) | ~0.03 s |

---

## 4. What the Suite Already Built On Top of pytest

This section answers "what functionality has been added on top of
pytest?" — it is the capability inventory BriXTest packages. None of this
is speculative; every row exists in the tree today (implementation
pointers into §5 and Appendix C).

### 4.1 The capability inventory

| Capability | What it does today | Implementation (today) |
|---|---|---|
| **Fleet orchestration** | 126 server instances described as declarative specs with dependency edges (`requires=`), started in dependency-leveled parallel waves, stopped with a one-sweep quiescence check; per-kind lifecycle for 6 kinds (nginx, xrootd, xrdhttp, haproxy, plain proc, external) | `server_registry` + `fleet_specs*` + `RegistryLauncher` (§5.2, §5.3) |
| **Readiness & endpoints** | per-spec readiness probes (registry path: protocol-named aliases over a TCP poll — see F4 for the measured gap; legacy path: protocol-level `xrdfs`); every instance resolves to a `ServerEndpoint` (host, port, extra ports, prefix, config, pidfile) tests consume instead of raw addresses | spec `readiness=` field; `_wait_ready` (§5.2); `lib_py` |
| **Declaration gate** | AST-scans test modules for which servers they use, *fails* tests that use undeclared servers, and boots **only the declared subset** of the fleet for the selected tests — with a persistent cross-session cache | `fleet_declares` + `conftest_part3` gate (§5.1) |
| **Fleet stability machinery** | A sentinel watchdog thread that aborts the session if the fleet dies while every test worker is blocked on a dead socket; a before/after process-conservation check; an orphan reaper; a startup-stability window | `conftest_part4` (§5.1) |
| **Artifact factory** | Generates a full security universe per lane: CA + 10-year server/user certs, 12-hour proxies (std/CMS/ATLAS), VOMS material, JWT issuers + JWKS + signed tokens, Kerberos KDC + keytabs, delegation certs — with a content-addressed cross-session snapshot cache (11.3 s cold → 0.03 s warm) | `fleet_prep`, `pki_helpers`, `tokenforge`, `x509forge`, `kdc_helpers` (§5.6) |
| **Lane isolation** | Concurrent suite runs coexist on one host via `TEST_ROOT` + `TEST_PORT_START` lanes; `TMPDIR` and `tempfile.tempdir` are confined to the lane tree so nothing leaks into `/tmp`; a foreign-lane refusal stops one lane from destroying another's live fleet | `settings` lane math, `conftest_part3:112-128`, conftest refusal (§5.10) |
| **Unprivileged operation** | Every port ≥ 1024 (fixed ladders 8080–29001, per-lane dynamic ranges from `port_ladder`); no root required except the explicitly `privileged`-marked multi-user lane, which runs under its own sudo wrapper | `settings` port families (Appendix D), `run_multiuser_authz.sh` |
| **Scheduling & timeout policy** | xdist `--dist=loadgroup`, `serial`/`privileged`/`leak`/`netfault` marker lanes, signal-based per-test timeouts chosen specifically so a hung test fails cleanly instead of killing an xdist worker into port-colliding reruns | `pytest.ini` (§5.9) |
| **Matrix testing** | `pytest_generate_tests`-driven parametrization of the same test body across backends/protocols/configs, with per-node fleet wiring | `matrix_layer`, `backend_matrix` (§5.1) |
| **Crash-isolated protocol clients** | All pyxrootd/XrdCl (C++) calls run in an out-of-process worker the parent kills on wall-clock timeout — a wedged native poller can never hang the pytest interpreter; plus HTTP/WebDAV/gridftp helpers and a PTY driver for interactive CLIs | `_xrdcl_worker`/`_xrdcl_proxy`, `guard_http_lib`, `cli_pty` (§5.5) |
| **Protocol stub servers** | 8 single-purpose counterpart servers (OCSP responder, OIDC, token introspection IdP, static origin, mirror-shadow, guard stub, proxy-minting forwarder, token-conformance server) registered as `proc` specs | `tests/lib/*.py` (Appendix C) |
| **Config templating** | 541 templates rendered per lane/instance with injected runtime values (paths, ports, module loads) | `render_nginx`/`render_cfg`, `config_templates` (§5.2) |
| **Operations CLI** | `start-all | stop-all | restart | status | start-dedicated` for humans and CI, plus 143 live-scenario scripts | `cmdscripts/manage_test_servers.py` (§5.4) |
| **Static conformance gates** | The declaration gate, port-documentation conformance, template-reference checking, size/complexity ratchets — the suite guards itself | `source_guards_lib`, `tools/ci/*` (§12) |

Approximate scale of the framework half (from Appendix C sums): the
conftest constellation ~2,700 LOC, launcher stack ~1,600, catalogue +
registry ~1,300, port machinery ~2,800, credential forges ~3,600,
clients ~1,300, stub servers ~1,240 — **on the order of 15k LOC of
framework** currently indistinguishable from the suite that uses it.

Each capability row above is formalized as a feature specification in
§7.3 (F1–F15): grown shape, designed parity surface, additive
enhancements, and failure modes. This table says what exists; §7.3 says
what each thing *becomes*.

### 4.2 Why plain pytest is not enough here

pytest's model is functions + fixtures inside one interpreter. Complex
server↔client testing adds needs pytest deliberately does not address,
and each one maps to a capability above (and to a documented incident
that forced it):

1. **Long-lived shared servers.** Thousands of tests exercise the *same*
   126 servers; per-test setup would take hours. → registry +
   session-scoped fleet + declaration-gated subset boot.
2. **Fleet ownership under parallelism.** xdist runs many workers but
   exactly one party may wipe trees and boot servers. → controller-only
   `_setup_session`, `workerinput` gating, gw0-only cache writes (§5.10).
3. **Liveness during the run, not just at start.** A fleet that dies
   mid-run must abort the session, not let every worker hang on dead
   sockets. → sentinel watchdog + conservation check.
4. **Real credentials with real lifetimes.** GSI/WLCG/KRB5 flows need
   actual CAs, proxies, tokens, keytabs — expensive to mint, dangerous
   to share across lanes. → the artifact factory + TTL'd snapshot cache.
5. **Port and path hygiene across concurrent runs.** Two lanes on one
   dev box, or CI beside a dev session, must not collide or reap each
   other (the cross-lane SIGTERM incident, history §10). → lanes,
   ladders, foreign-lane refusal, substring-safe reaping.
6. **Native-library crash isolation.** A C++ client library that
   deadlocks or SIGSEGVs must not take the test runner with it. →
   out-of-process client workers.
7. **Orphan control.** Aborted runs must not leave listeners squatting
   on fixed ports. → orphan reaper + `owns()` + kill tracer.
8. **Config-space coverage.** The same behavior must hold across
   hundreds of server configurations. → template rendering + matrix
   layer + spec catalogue.

These eight needs are generic to any server↔client system. That is the
case for extracting BriXTest (§6–§7): nothing in the *mechanics* above is
nginx- or XRootD-specific; only the specs, templates, kind
implementations, and credential recipes are.

---

## 5. Current-State Anatomy (what exactly is being reorganized)

This section is the ground truth the migration mechanics in §10–§11 refer
back to. It was read off the code on 2026-08-17, not off older docs.

### 5.1 The conftest constellation: who defines which hook

| File | LOC | pytest hooks | Load-bearing internals |
|---|---|---|---|
| `conftest.py` | 514 | *(none — anchor module)* | `_install_kill_tracer`, `_chdir_scratch`, `_ensure_client_x509_env`, `_seed_canonical_data`, `_reset_session_tree_once`, `_external_fleet_attached`, `_fleet_main_master_alive`, `_should_skip_local_lifecycle`, lane-refusal error ("owned by another or incomplete test fleet"), session fixtures `requires_ipv6_loopback`, `requires_krb5`; execs parts 2–5 at lines 512-514 |
| `conftest_part2.py` | 460 | `pytest_sessionstart` | `_setup_session` (tree wipe → data seed → 200 MiB gen → `fleet_prep.prepare()` → `freeze_nginx`), `_reap_leaked_test_servers`, `_register_fleet`, `_start_all_resilient`, `_stop_owned_fleet`, `_xdist_requested`, `_validate_requested_paths`; collectonly early-return gate |
| `conftest_part3.py` | 609 | `pytest_configure`, `pytest_collection_modifyitems` | TMPDIR+`tempfile.tempdir` pinning to `TEST_ROOT/tmp`; marker registration; `_pytest_config` global; the server-declaration gate (`_enforce_server_declarations`, `_declaration_violations`, `_module_test_usage`, `_specs_to_boot`, `_autouse_specs_for`) and its persistent `config.cache` layer (`_declare_disk_*`, `_flush_declare_cache`, gw0-only writes) |
| `conftest_part4.py` | 536 | *(none)* | Fleet stability/conservation machinery: `_capture_fleet_baseline`, `_verify_fleet_conservation`, `_require_fleet_startup_stability`, sentinel watchdog (`_sentinel_*`, `_start_sentinel_watchdog`), kill-diag |
| `conftest_part5.py` | 450 | `pytest_runtest_setup`, `pytest_runtest_teardown`, `pytest_collection_finish`, `pytest_sessionfinish`, `pytest_terminal_summary`, `pytest_generate_tests` | Fixtures: `registry` (session), `registry_server`, `lifecycle`, `command_runner`, `matrix_node` (module), `test_env` (session), `ref_xrootd`, `ref_brix_gsi`, `ref_brix_gsi_shared` (session); collectonly gates; post-collection fleet boot; stop sweep + tree destruction |
| `conftest_mu.py` | 112 | `pytest_terminal_summary` | Multi-user fixtures: `cast`, `mu_fleet`, `apply_policy`, `revoke`; `_seed_export` |

Ordering constraints that MUST survive extraction verbatim:
`pytest_configure` (part3) runs on controller **and every xdist worker**
before any test; `pytest_sessionstart` (part2) returns early for workers
(`workerinput`) and for `--collect-only`; the fleet boots either from
`pytest_collection_finish` (non-xdist, declared-subset boot via
`_specs_to_boot`) or from sessionstart (xdist controller, full fleet);
`pytest_sessionfinish` order is conservation check → stop sweep → orphan
alarm → tree destruction.

**Fixture surface** (source of truth for the TS-2 `fixtures.py` move —
scope and dependency edges must survive byte-identically):

| Fixture | Scope | Signature deps | Defined at |
|---|---|---|---|
| `registry` | session | — | `conftest_part5.py:281` |
| `test_env` | session | — | `conftest_part5.py:363` |
| `ref_xrootd` | session | `test_env` | `conftest_part5.py:427` |
| `ref_brix_gsi` | session | `test_env` | `conftest_part5.py:436` |
| `ref_brix_gsi_shared` | session | `test_env` | `conftest_part5.py:445` |
| `registry_server` | function | — | `conftest_part5.py:286` |
| `lifecycle` | function | — | `conftest_part5.py:294` |
| `command_runner` | function | `registry` | `conftest_part5.py:309` |
| `matrix_node` | module | `request, tmp_path_factory` | `conftest_part5.py:340` |
| `requires_ipv6_loopback` | session | — | `conftest.py` |
| `requires_krb5` | session | — | `conftest.py` |
| `cast` | session | — | `conftest_mu.py:16` |
| `mu_fleet` | session | `cast` | `conftest_mu.py:43` |
| `apply_policy` | function | `cast` | `conftest_mu.py:69` |
| `revoke` | function | `cast` | `conftest_mu.py:96` |

### 5.2 The launcher anatomy

| File | LOC | Contents |
|---|---|---|
| `server_launcher.py` | 108 | module helpers `_nginx_bin`, `_inject_nginx_load_modules`, `_inject_nginx_runtime_paths`; `launch_fleet_nginx`; execs part2+part3 |
| `server_launcher_part2.py` | 42 | `class RegistryLauncher(_MixinA, _MixinB, _MixinC)` — assembly only |
| `_server_launcher_part2_mixina.py` | 467 | **start side**: `__init__`, controller/worker manifests, `start_registered` (dependency-leveled, parallel workers), `_start_guarded`, `_dependency_levels`, `stop_registered` + `_quiescent` (one-sweep listener survey), `start` dispatch, per-kind starters `_start_xrootd`, `_start_xrdhttp`, `_start_haproxy`, `_start_proc`; duplicates the 3 module helpers |
| `_server_launcher_part2_mixinb.py` | 411 | **render/stop side**: `_start_external`, `render_nginx`/`render_nginx_like`, `_public_cadir` (the deliberately 0555 CA-dir), `_dedicated_data_tree`, `nginx_test`, `start_nginx`/`stop_nginx`/`stop`, `_reap_orphan_nginx_workers`, `reload`/`reopen`/`restart`, `kill_worker`, `process_snapshot`; duplicates the 3 module helpers |
| `_server_launcher_part2_mixinc.py` | 373 | **privileged/fs + waiting side**: `_xrootd_runas_user`, `_chown_r`/`_chmod_*`, `_session_values`, `_endpoint_template_values`, `_nginx` (invocation), `_wait_ready`, `_wait_ports_released`, `_stop_from_disk`, `_kill_xrootd`, `_read_pid`/`_kill_pidfile`; duplicates the 3 module helpers |
| `server_launcher_part3.py` | 170 | `class LifecycleHarness` — the per-test facade (`register`, `start`, `endpoint`, `reconfigure`, `reload`, `restart`, `stop`, `kill_worker`, `expect_config_failure`, `run_privileged_step`, `close`) used by the `lifecycle` fixture |
| `server_launcher_errors.py` | 28 | launcher exception types |

Kind-dependent behavior currently lives in `if spec.kind ==` ladders spread
across mixina (start dispatch, `_quiescent` pidfile locations), mixinb
(`stop` verb selection), and mixinc (`_stop_from_disk`, `_kill_xrootd`):
nginx → `prefix/logs/nginx.pid`, `-s quit`; xrootd/xrdhttp →
`prefix/run/xrootd.pid`, signal-based; haproxy → `prefix/logs/haproxy.pid`;
proc → port-tracked only; external → never stopped, never quiescent-skipped.

### 5.3 The registry and spec catalogue

`server_registry.py` (module-global `_SPECS: dict[str, NginxInstanceSpec]`)
exports: `clear_registry`, `register_nginx`, `register_xrootd`,
`unregister`, `replace_spec`, `register_command_suite`, `registered_specs`,
`declared_ports`, `port_conflicts`, `registered_command_suites`,
`dependency_order`, `endpoint_for`, plus dataclasses:

- `NginxInstanceSpec` (15 fields): `name, template, port, protocol, host,
  data_root, extra_ports, env, template_values, readiness, requires, tags,
  allow_remote_skip, reason, kind`
- `CommandSpec` (7 fields): `name, argv, env, timeout, requires, tags, reason`
- `ServerEndpoint` (9 fields): `name, host, port, protocol, data_root,
  extra_ports, prefix, config, pidfile`

The catalogue lives in `fleet_specs.py` (`core_specs`,
`xrootd_backend_specs`, `support_specs`, feature probes `_nginx_has_krb5`,
`_xrdcp_bin`) and `fleet_specs_part2.py` (`ha_specs`, `dedicated_specs`,
`register_full_fleet`, `_all_specs`), parameterized by `fleet_values.py`
— part2 exec'd into part1's namespace at `fleet_specs.py:405` (§2.3).
Measured composition of `register_full_fleet()` (2026-08-17):

| Builder | Specs | Kind breakdown |
|---|---|---|
| `core_specs()` | 7 | 1 nginx (`main`) · 5 xrootd (`ref-anon`, `ref-gsi`, `ref-gsi-shared`, `root-tpc-ref`, `pss-bridge`) · 1 xrdhttp (`xrdhttp`) |
| `xrootd_backend_specs()` | 9 | 9 xrootd |
| `support_specs()` | 10 | 6 proc (`static-origin`, `mirror-shadow`, `guard-stub`, `introspect-idp`, `cms-parent-stubs`, `upstream-stubs`) · 3 external (`krb5-kdc`, `cms-mesh`, `hybrid-mesh`) · 1 nginx |
| `ha_specs()` | 3 | `ha-haproxy` · `ha-nginx1` · `ha-nginx2` |
| `dedicated_specs()` | 97 | nginx dedicated roles |
| **Total** | **126** | nginx 101 · xrootd 14 · proc 6 · external 3 · haproxy 1 · xrdhttp 1 |

Only `main` and `ref-anon` carry the `critical` tag (start-all aborts on
their failure). The catalogue docstring records that **414 test files
import the fixed port constants** — the reason ports are pinned to
`settings` names rather than OS-assigned, and the reason `PortLedger`
(§9.2.1) must preserve those names one-for-one.

### 5.4 The CLI and script surface

- `cmdscripts/manage_test_servers.py`: verbs `start-all | stop-all |
  restart | status | start-dedicated`; run as
  `python3 -m cmdscripts.manage_test_servers` **from `tests/`**.
  143 further `cmdscripts/*.py` live-scenario scripts sit beside it.
- `tests/manage_test_servers.py` (top-level, 24 lines) is **not** a
  forwarder to the above — it is a bash-era tombstone whose
  `start_servers`/`restart_servers` raise `RuntimeError` telling callers
  to use fixed dedicated roles; its docstring and error text still
  reference `tests/manage_test_servers.sh`, dissolved 2026-07-18. It
  exists to make an obsolete import fail loudly, and the migration must
  preserve exactly that property (Appendix A row updated accordingly).
- `run_suite_unprivileged.py`, `run_multiuser_authz.sh` (sudo path),
  `manage_test_servers`-driven fleet ops in docs/recipes.

### 5.5 The utility stratum

`lib_py/util.py` (12 functions: `run`, `render_cfg`, `have_cmd`,
`find_xrd_library`, `find_xrd_sec_lib`, `pids_on_port`,
`listening_port_pids`, `pids_in_port_range`, `process_age`,
`kill_pid_list`, `wait_tcp`, `wait_ready_xrdfs`) is the de-facto process/
port toolkit. Beside it: `ephemeral_port.py`, `config_parse.py`,
`config_templates.py`, `metrics_helpers.py`, `matrix_layer.py`,
`frm_helpers.py`, `tpc_parse_helpers.py`, `guard_http_lib.py`, `cli_pty.py`
— each single-purpose, none packaged.

### 5.6 Crypto/token strata

`pki_helpers.py` (blitz PKI, 10-year certs, SAN handling),
`utils/make_proxy.py` (12 h proxies — note: lives in repo-root `utils/`,
not `tests/`), `utils/make_token.py`, `tokenforge.py` (+2 parts, 4 mixins;
`TokenForge(TokenIssuer)` + `Manifest`), `x509forge.py` (+2 parts; `Cert`),
`token_differential.py`, `x509_differential.py`,
`x509_matrix_differential.py`, `kdc_helpers.py`, `mint_delegation_certs.py`,
`fleet_prep.py` (artifact pipeline + cross-session snapshot cache under
`~/.cache/nginx-xrootd/fleet-prep/`, history §11).

### 5.7 The infra-internal dependency graph (AST-measured, 2026-08-17)

`import`/`from` edges among the infra modules themselves (test files
excluded) — this is the graph the package layering in §9.1 must respect,
and the order the alias shims must be able to satisfy:

**Layering as it actually exists** (arrows = "imports"):

```
Layer 0  port_ladder                    ← settings imports port_ladder, not vice versa
Layer 1  settings (→ port_ladder)
Layer 2  server_registry, config_templates, fleet_values, pki_helpers,
         metrics_helpers, kdc_helpers, guard_http_lib, cms_parent_stubs,
         upstream_protocol_stubs, backend_matrix   (→ settings only)
Layer 3  fleet_ports_{exclusive,shared_phase5,shared_waves} → fleet_lifecycle_ports
         ephemeral_port (→ port_ladder)
Layer 4  server_launcher (+ mixins) → cmdscripts, config_templates,
         fleet_lifecycle_ports, fleet_values, lib_py, server_launcher_errors,
         server_registry, settings
Layer 5  cms_mesh_lib / hybrid_mesh_lib / wlcg_fleet (→ launcher, mesh_config)
Layer 6  fleet_specs → cms_mesh_lib, hybrid_mesh_lib, server_launcher,
         server_registry, settings
Layer 7  fleet_ports → fleet_specs · fleet_declares → fleet_ports, fleet_specs
Layer 8  fleet_prep → cmdscripts, pki_helpers
Layer 9  conftest constellation → fleet_declares, fleet_orphans, fleet_prep,
         fleet_specs, server_launcher, server_registry, settings,
         matrix_layer, ephemeral_port
```

Structural facts the target layout must honor:

- **`settings` → `port_ladder`** is the bottom edge: ports math sits
  *below* configuration. `brixtest.config.ports` therefore may not import
  the settings layer — the dependency points the other way, exactly as
  today.
- **`fleet_ports` imports `fleet_specs`** (the port tables are derived
  from the spec catalogue), while `fleet_lifecycle_ports` imports only
  the three `fleet_ports_*` table modules. The TS-3/TS-4 consolidation
  must keep `catalogue → launcher → lifecycle_ports → tables` acyclic
  and put the spec-derived aggregation (`fleet_ports`) above the
  catalogue, as now.
- **The mixin ↔ `server_launcher` circularity** (§2.3) is the one edge
  that must NOT be preserved: `nginx_tools.py` removes the mixins'
  reason to import the launcher module at all.
- `fleet_prep → cmdscripts` and `run_suite_unprivileged → fleet_orphans`
  are the two edges that cross from library code into CLI territory;
  both invert naturally when `cli/` becomes the top layer (TS-5).
- `token_differential → lib` (the stub-server package) is the only
  security-module edge into `servers/` — the vectors module drives a live
  stub; it moves with `brix_suite.security.tokens_vectors` and keeps the
  edge.

The full adjacency list is reproduced in Appendix C alongside per-module
LOC, so shim ordering for any phase can be read off one table.

### 5.8 The environment contract (what settings construction must honor)

Two tiers of environment input, measured across the infra modules:

**Tier 1 — settings-owned overrides.** Every one of the 258 `settings`
exports follows `X = <cast>(os.environ.get("TEST_X", default))`: 178
ports, 39 roots/dirs, 41 other. These migrate wholesale into
`SuiteSettings.from_env` / `PortLedger` and need no individual listing
(the ports side is guarded by `check_ports_doc.py` already).

**Tier 2 — runtime knobs read outside `settings.py`** (grep of
`os.environ` across the conftest constellation, launcher, registry,
prep, forges, `lib_py/`, and the CLI — these are the knobs with *no*
current single home, which is exactly what `SuiteSettings` fixes):

| Variable | Read by | Effect |
|---|---|---|
| `TEST_SKIP_SERVER_SETUP` | conftest (×3) | session does no local server work |
| `TEST_OWN_FLEET` | conftest | force lifecycle ownership |
| `TEST_FLEET_STABILITY_SECS` | conftest_part4 | startup-stability window |
| `BRIX_FLEET_SENTINEL` (+`_POLL`, `_GRACE`, `_FRACTION`, `_MIN_DOWN`, `_ABORT`) | conftest_part4 | watchdog enable + 5 tuning knobs |
| `BRIX_FLEET_PREP_CACHE` | fleet_prep | artifact-snapshot cache kill-switch (history §11) |
| `BRIX_FLEET_START_WORKERS` | launcher | parallel-start worker count |
| `XDG_CACHE_HOME` | fleet_prep | snapshot cache root |
| `PYTEST_XDIST_WORKER` | launcher | worker-side manifest behavior |
| `SANITIZE`, `SANITIZE_LOG_DIR` | launcher/settings-adjacent | ASan binary + log routing |
| `VALGRIND`, `VALGRIND_LOG_DIR` | launcher | valgrind wrap |
| `NGINX_CONF_PREGENERATED`, `NGINX_CONF_REL` | launcher render | pre-rendered config paths |
| `REF_RUNAS_USER` | mixinc | xrootd run-as user |
| `LARGE_FILE_SEED` | data seeding | deterministic large-file content |
| `SKIP_XRDFS_CHECK` | `lib_py` legacy start path | skip the protocol-level xrdfs probe (legacy generation only — see F4) |
| `BRIX_TEST_USER`, `BRIX_TEST_TREE`, `FWD_PORT_BASE` | multiuser/fwd suites | privileged-lane identity |
| `CONFIGS_DIR`, `PKI_DIR`, `NGINX_BIN`, `BRIX_BIN`, `XRDCP_BIN`, `XROOTD_BIN`, `REF_BIN`, `REF_DIR`, `XRDHTTP_DIR`, `XRDHTTP_DATA_DIR` | lib_py / launcher | path overrides that bypass `settings` (a duplication `SuiteSettings` retires) |

TS-3 gives every Tier-2 knob a `SuiteSettings` field with its current
default; the doc table above becomes the checklist. New knobs after TS-3
must be fields first, env second.

### 5.9 pytest configuration and the marker taxonomy

Root `pytest.ini` (verbatim policy content, comments elided): `timeout =
30`, `timeout_method = signal` (a deliberate choice with a long inline
rationale — `thread` kills whole xdist workers and forces port-colliding
reruns; safe only because all XrdCl calls live in the out-of-process
worker), `addopts = -v --dist=loadgroup`, `pythonpath = tests`,
`testpaths = tests` (the §2.2 shadowing fix), one urllib3 warning filter,
and **13 declared markers**: `slow`, `large`, `e2e`,
`requires_local_server`, `serial`, `privileged`, `leak`, `netfault`,
`tokenconf`, `optin`, `x509conf`, `selinux` (+1 spare). `conftest_part3.py:129-156`
additionally registers 4 markers dynamically — `requires_local_server`,
`leak`, `privileged`, `uses_lifecycle_harness` — meaning marker
registration currently has **two homes**; TS-2 consolidates all
registration into the plugin's `pytest_configure` and leaves `pytest.ini`
markers as declarations only. The ini file itself does not move before
TS-7 (§15 recommendation).

### 5.10 Verbatim invariants and the harness pinning suite

Two code blocks so load-bearing they are reproduced here as the
byte-comparison reference for TS-2 (any diff beyond import paths is a
review blocker):

`conftest_part3.py:112-128` — the TMPDIR confinement (runs on controller
AND every xdist worker; the reason nothing may cache under
`tempfile.gettempdir()`, history §11):

```python
def pytest_configure(config):
    ...
    global _pytest_config
    _pytest_config = config
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ["TMPDIR"] = TMP_DIR
    tempfile.tempdir = TMP_DIR
```

`conftest_part2.py:405-436` — the sessionstart gate order: collectonly
early-return FIRST (before the sentinel watchdog), then watchdog start,
then the worker branch (`workerinput`) which runs `_ensure_client_x509_env()`
but deliberately does **not** chdir before collection ("xdist workers
must still resolve relative args") and returns before
`_validate_requested_paths`. The inline comments in that block encode
three past incidents; they move verbatim.

**The harness pinning suite** — the tests that must stay green,
unmodified, through every TS-2/TS-3/TS-4 commit (67 test functions
total): `test_conftest_fleet_lifecycle.py` (loads the conftest under
test by path as `tests_conftest_under_test`, §2.5),
`test_server_registry_smoke.py`, `test_fleet_prep_cache.py`,
`test_fleet_teardown_orphans.py`. TS-2 keeps the by-path loader working
against the shimmed `conftest.py`; converting these tests to import
`brixtest.harness.*` directly (retiring the duplicate-execution
loader) is the very first TS-7 tranche, since it is the one test-side
change that deletes a §2.2-class hazard.

---

## 6. Goals and Non-Goals

### Goals

- **G1 — Installable project.** `BriXTest/` with `pyproject.toml`, `src/`
  layout, pinned metadata, declared dependencies (core + extras), console
  entry points. `pip install -e BriXTest/` replaces `PYTHONPATH=tests`
  for all infrastructure imports.
- **G2 — Cohesive subpackages with real classes.** A constructed,
  validated settings object; a launcher whose parts are ordinary modules;
  a data-driven kind model; the harness as a named pytest plugin;
  crypto/token forges as normal class hierarchies.
- **G3 — `split_continuation.load` retired from infrastructure.** (The
  253 test-side `reexport` users are Phase TS-7's separate, optional tail.)
- **G4 — Every existing entry point keeps working throughout:**
  `pytest tests/…` (with and without `-n`), `python3 -m
  cmdscripts.manage_test_servers`, `run_suite_unprivileged.py`,
  `run_multiuser_authz.sh`, lane env knobs (`TEST_ROOT`,
  `TEST_PORT_START`, `TEST_SKIP_SERVER_SETUP`, `TEST_OWN_FLEET`, remote
  mode), all guards, the k8s interop harness.
- **G5 — Incremental and shimmed.** At no point does a tranche of 1,019
  test files need a same-day rewrite. Every commit leaves both the old and
  new import names working.
- **G6 — A generic core.** `brixtest` contains no nginx-, XRootD-, or
  WLCG-specific knowledge; the import direction `brix_suite → brixtest`
  is one-way and guard-enforced (§7.2). A second product could adopt
  BriXTest by writing its own adapter.
- **G7 — Deployment as a seam.** All process mechanics live behind a
  backend interface whose first implementation (`LocalBackend`) is
  behavior-identical to today's launcher — unprivileged, lane-scoped,
  fork/exec — and whose design does not preclude a Kubernetes backend
  (§8). The k8s backend itself is future work (TS-9), not this plan's
  deliverable.

### Non-Goals (this plan)

- **NG1** — No test file moves or edits until TS-7 (separately approved).
- **NG2** — No behavior change: no port/lane semantics, no fixture
  renames, no fleet lifecycle changes, no timing regressions.
- **NG3** — No repackaging of `k8s-tests/remote-suite` (in-cluster suite);
  §8 designs the seam that could later unify it, nothing more.
- **NG4** — No test-framework or plugin swap-outs (pytest + xdist +
  timeout + rerunfailures stay).
- **NG5** — No rewriting of the 143 `cmdscripts` live scenarios beyond
  import shims; their content is test-side.
- **NG6** — No speculative abstraction: genericity is achieved by the
  promotion rule of §7.2 (extract, then generalize on evidence), never by
  designing interfaces for hypothetical consumers.

---

## 7. BriXTest: The Framework

### 7.1 Identity

- **Project / distribution name:** `brixtest` (spelled **BriXTest** in
  prose), one wheel containing two top-level packages:
  `brixtest` (generic core) and `brix_suite` (nginx-xrootd adapter).
  Splitting the adapter into its own distribution later is a metadata
  change, not a code move.
- **Tagline that fixes the scope:** *generic server/client test
  config, deployment, and management* — specs in, running fleet out,
  pytest-native consumption, local-unprivileged today, containerized
  tomorrow.

### 7.2 The genericity contract

The core/adapter boundary is enforced by three rules, not by taste:

1. **Import direction.** `brixtest` never imports `brix_suite` (new
   guard #8, §12). The adapter registers its knowledge into the core at
   activation time (conftest / CLI startup), never the reverse.
2. **The promotion rule.** Every module lands in the **adapter by
   default**. A module is promoted to `brixtest` core only when it (a)
   has zero product-specific imports and vocabulary, and (b) implements
   one of the §4.1 capabilities rather than suite policy. Promotion is a
   rename inside the same distribution — cheap, reviewable, reversible.
   This is how the plan avoids premature-abstraction risk (R11): the
   migration phases (§11) are *moves*; genericity is an overlay applied
   where the seam is already obvious.
3. **Data over subclassing at the boundary.** The adapter feeds the core
   *data* (spec catalogues, `KindProfile` rows with starter/renderer
   callables, artifact-pipeline steps, settings instances) through
   registration APIs — not by subclassing core internals. The core's
   extension points are exactly: kind registration, artifact-step
   registration, backend selection, and the plugin's session-lifecycle
   configuration.

Already-known promotion candidates (generic on inspection, §5): the spec
registry and dataclasses (renamed `InstanceSpec`; `NginxInstanceSpec`
remains as the adapter's alias), the dependency-leveled start/stop engine,
the `KindProfile` mechanism, the declaration gate (AST usage scan +
subset boot + cache), the sentinel/conservation machinery, lane/port-ledger
machinery, the artifact-snapshot cache engine (generic content-addressed
store; the *steps* are adapter), the out-of-process client-worker
pattern, `cli_pty`, and the proc/port utility stratum. Known
non-candidates: the 126-spec catalogue, nginx/xrootd/haproxy kind rows
and renderers, the WLCG/GSI/KRB5 forges, the stub servers, mesh/interop/
cachemx/perf libraries, the 258-field `SuiteSettings`.

### 7.3 The feature catalogue (F1–F15)

Every §4.1 capability exists today as *grown* code — behavior that
accreted where it was needed, correct but shaped by accident of history.
BriXTest re-states each one as a *designed* feature. Each specification
below has four fixed parts:

- **Grown today** — the current shape and what is wrong with it
  (evidence pointers into §2/§5; the behavior itself is not wrong).
- **Designed surface (parity)** — the API the migration delivers with
  **byte-identical behavior**. Parity surfaces are what the TS-phases
  (§11) actually land; NG2 applies to them absolutely.
- **Designed additions (additive, post-parity)** — enhancements the
  designed shape makes cheap. These are **never** part of a migration
  commit: each lands separately, after its feature's parity phase has
  soaked, behind its own gate (risk R13).
- **Failure modes** — the named exceptions the feature may raise, drawn
  from the §7.5 taxonomy. A grown `RuntimeError` with a string is not an
  acceptable designed failure.

Every feature also names its home (core `brixtest` vs adapter
`brix_suite`) per the §7.2 promotion rule, and its verification triad
(success + error + security-negative) per the repo's 3-tests rule.

**The lifecycle spine.** The fifteen specs share one instance
lifecycle. Today these states exist only implicitly — the fleet "is"
whatever the pidfiles and listeners imply, and the sole reified state
is the fleet-ready marker file. BriXTest names them, which is what
makes the F15 events, the F14 `status` output, and the C1 error
messages one vocabulary instead of three:

| State | Entered when | Owner | F15 event | Exits to |
|---|---|---|---|---|
| `REGISTERED` | spec accepted into the registry | F1 | — | `PREPARED`; refusal is `RegistrationError`, never a state |
| `PREPARED` | config rendered, dirs laid out | F2/F13 | — | `STARTING` |
| `STARTING` | starter spawned via the backend | F3/F9 | `spec.start` | `READY` · `FAILED` |
| `READY` | declared probe satisfied | F4 | `spec.ready` | `STOPPING` · `DIED` |
| `STOPPING` | stop dispatched per kind profile | F3/F2 | `spec.stop` | `STOPPED`; a survivor is `QuiescenceError` |
| `STOPPED` | quiescence proven | F3 | — | terminal |
| `FAILED` | start or readiness failed | F3 | `spec.fail` | terminal; the critical-tag policy decides session fate |
| `DIED` | sentinel-confirmed death (dead ≥ grace) | F6 | `sentinel.trip` | terminal; abort per `StabilityPolicy` |

Parity note: the transitions are exactly today's behavior — only the
*names* and their observability are new, so the table is additive
documentation, not a behavior change (NG2).

---

#### F1 — Declarative instance model and registry

**Definition.** A server instance is data: a validated, serializable
spec. The registry is the single authority on what instances exist,
their ports, and their dependency order.

**Grown today.** `NginxInstanceSpec` (15 fields, §5.3) is honest data,
but nothing validates it: `kind` and `readiness` are bare strings,
`requires` edges are checked only when dependency-leveling happens to
run, and port collisions surface only if someone calls
`port_conflicts()`. The registry is a module global (`_SPECS`) imported
flat by 330 modules; specs are not serializable, so no tool outside the
process can see the fleet.

**Designed surface (parity).** `brixtest.fleet.registry` (core), alias-
shimmed (§10.2). `InstanceSpec` is the canonical name
(`NginxInstanceSpec = InstanceSpec` preserved); the full function
surface of §5.3 moves unchanged; `_SPECS` stays a single process-wide
instance by construction of the alias shim.

The field contract, written down — types are today's de-facto types
(parity validates nothing new); the last column is what F1's additive
strict mode will check, one rule per field instead of folklore:

| Field | Type | Designed validation (additive, strict mode) |
|---|---|---|
| `name` | `str` | non-empty; unique in registry; kebab-case by convention (`ref-gsi`) |
| `kind` | `str` | names a registered `KindProfile` (F2) |
| `template` | `str \| None` | resolves via `asset()` when the kind has a renderer (F13) |
| `port` | `int` | ≥ 1024; unique across every spec's `port` + `extra_ports` |
| `extra_ports` | `tuple[int, ...]` | same uniqueness rule |
| `protocol` | `str` | member of the adapter's protocol vocabulary |
| `host` | `str` | non-empty; core never assumes loopback (§8.4 rule 2) |
| `data_root` | `str` | resolves inside the lane root (the F1 security-negative) |
| `env` | `Mapping[str, str]` | keys non-empty |
| `template_values` | `Mapping[str, str]` | participates in F13's unresolved-placeholder scan |
| `readiness` | `str` | known probe alias (F4) — today an unknown alias is a `ValueError` at *start* time; strict mode moves the check to registration |
| `requires` | `tuple[str, ...]` | every edge resolves at fleet-freeze; the graph is acyclic |
| `tags` | `frozenset[str]` | vocabulary-checked (`critical`, …) with a documented escape hatch |
| `allow_remote_skip` | `bool` | — |
| `reason` | `str` | required when `allow_remote_skip` is set |

**Designed additions (additive).**
- Eager registration-time validation — duplicate name, port collision,
  unknown kind, dangling `requires` edge — behind a strict flag that
  ships warn-only for one phase (same discipline as §11 TS-3 item 6).
- `InstanceSpec.to_dict()` / `from_dict()` round-trip, the enabler for
  `brixtest fleet status --json` (F14) and the K8sBackend manifest
  translation (F9): a spec that cannot leave the process cannot become
  a Deployment.

**Failure modes.** `SpecError` (bad field), `RegistrationError`
(duplicate/collision/dangling edge), `UnknownKindError`.

**Triad.** Register-and-resolve round trip · duplicate-port
registration refused with both spec names in the message ·
security-negative: a spec whose `data_root` escapes the lane root is
refused at registration.

**Home.** Core; the 126-spec catalogue stays adapter (§5.3).

---

#### F2 — Kind profiles

**Definition.** Everything kind-specific — how to start, stop, render,
find the pidfile, judge quiescence — is one table row plus two
callables, not branches.

**Grown today** (measured). Six kinds — `nginx` (the unmarked default),
`xrootd`, `xrdhttp`, `haproxy`, `proc`, `external` — dispatched by
`if spec.kind ==` ladders at seven sites across the three mixin files:
the five-way start ladder (`mixina:223-237`), the quiescence-skip
ladder with its inline pidfile spellings (`mixina:204-220` —
`run/xrootd.pid` for xrootd/xrdhttp, `logs/haproxy.pid` for haproxy,
`proc` port-tracked only, `external` never touched), the stop
dispatch (`mixinb:252` routes all five non-nginx kinds to
`_stop_from_disk`; nginx alone gets `-s quit` plus pidfile-SIGTERM
fallback), a render guard (`mixinb:396`), and three per-kind branches
in mixinc (257/267/276). Catalogue distribution: of the 126 specs,
109 are nginx, 6 xrootd, 6 proc, 3 external, 1 xrdhttp, 1 haproxy. A
new kind means finding every ladder; the launcher review burden grows
with each.

**Designed surface (parity).** `KindProfile` + the six rows of §9.2.2,
consulted by start dispatch, `stop`, `_quiescent`, `_stop_from_disk`.
Behavior per kind is pinned by the existing contract tests before and
after each ladder flip (§11 TS-4 item 5).

**Designed additions (additive).**
- `brixtest.fleet.kinds.register(profile)` as the public extension
  point — a consumer adds a kind without touching core.
- An exported contract-test kit, `brixtest.testing.kind_contract` — a
  parametrized suite any registered kind must pass, its six cases
  drawn from the measured ladder semantics above:
  1. start → ready → stop leaves no pidfile and no listener;
  2. stopping an already-dead instance is an idempotent no-op;
  3. one instance's stop failure never blocks visiting the others;
  4. the quiescence verdict matches the profile's declared mode
     (pidfile-tracked vs ports-only vs never);
  5. the pidfile location comes from the row, never a literal;
  6. a `stop="never"` profile is never signalled by any stop path.

  New kinds arrive with their proof, not with a review argument.

**Failure modes.** `UnknownKindError` at registration and at start
dispatch (today: a silent fall-through or ad-hoc `RuntimeError`).

**Triad.** Six rows drive the existing launcher contract suite · start
dispatch on an unregistered kind raises `UnknownKindError` naming the
known kinds · security-negative: a profile with `stop="never"` (external)
is never signalled by any stop path.

**Home.** Mechanism core; rows + starters + renderers adapter
(`brix_suite.kinds`, `nginx_tools`).

---

#### F3 — Fleet orchestration engine

**Definition.** Given registered specs, compute a dependency-leveled
plan, execute it with bounded parallelism, and stop everything with a
quiescence proof — deterministically, idempotently, and inspectably.

**Grown today.** `start_registered` builds dependency levels and starts
them with parallel workers (worker count from a bare env var,
`BRIX_FLEET_START_WORKERS`); failure policy is the `critical` tag
(only `main` + `ref-anon`, §5.3); `stop_registered` does the one-sweep
listener survey. All of it works; none of it is observable — the plan
exists only transiently inside the method, per-spec outcomes exist only
as log lines, and "start when already running" behavior is whatever the
code happens to do.

**Designed surface (parity).** `brixtest.fleet.launcher` (core engine,
§9.2.3): same leveling, same parallelism, same critical-tag policy, same
one-sweep stop; `BRIX_FLEET_START_WORKERS` becomes a `SuiteSettings`
field with the env fallback (§5.8).

Measured parity anchors (mixina): the entry point is
`start_registered(specs=None) -> dict` returning the controller
manifest; the worker default is `min(16, 2 × cpu_count)` — deliberate
oversubscription, because a start is wait-dominated (readiness polls,
subprocess exec latency), with `1` forcing the sequential legacy path
for deterministic debugging. Both the formula and the rationale move
verbatim; the rationale graduates from an inline comment to the
`StabilityPolicy`-style documented default (§7.5 C2).

**Designed additions (additive).**
- `FleetPlan` — the computed levels as a first-class object; `brixtest
  fleet plan` prints it (F14). What the engine will do becomes
  reviewable before it does it.
- `StartReport` — per-spec outcome (started / already-running / failed /
  skipped-remote), wall-time, and log-path pointer, returned by
  `start_registered` and rendered by the CLI and the F15 event stream.
- A *defined* idempotence rule: starting a spec whose pidfile is live
  and whose ports answer is a no-op reported as `already-running`
  (today's de-facto behavior, promoted to contract and pinned by test).

Sketch of the two additive objects (shape, not final signature):

```python
@dataclass(frozen=True)
class FleetPlan:
    levels: tuple[tuple[str, ...], ...]   # spec names by dependency depth
    workers: int                          # resolved, not the env string
    backend: str                          # "local" | "k8s" (F9)

@dataclass(frozen=True)
class SpecOutcome:
    spec: str
    result: str            # started | already-running | failed | skipped-remote
    elapsed: float
    log: Path | None

class StartReport:         # Sequence[SpecOutcome]; .ok; renders as table/JSON
    ...
```

**Failure modes.** `StartError(spec, phase, log_tail)` — with
`RegistryCommandFailure` (§5.2's one rich grown exception: command,
returncode, config path, logs dir, stdout/stderr tails) surviving as its
concrete subclass so the 330 dependents' `except` clauses keep working;
`QuiescenceError(survivors)` on stop.

**Triad.** Full-fleet plan/start/stop round trip (the §14 gate) ·
stop-failure test: one failing stop still visits every spec ·
security-negative: the engine never signals a process whose pidfile it
did not write (ownership rule, F6).

**Home.** Core.

---

#### F4 — Readiness probes and endpoints

**Definition.** "Up" is a probe the spec declares and the backend
executes; "where" is an endpoint object, never a hand-built address.

**Grown today** (measured — `mixinc:194` + `lib_py`). The registry
path's `readiness` field accepts the alias set `{root, webdav, s3,
metrics, cms, tcp, none}` — names that *look* like protocol probes but
all collapse to a single TCP connect poll with a hard-coded 10 s
deadline; any other string raises `ValueError` at start time, not
registration time. Genuine protocol-level probing
(`wait_ready_xrdfs`, gated by `SKIP_XRDFS_CHECK`) exists only on the
bash-era `lib_py` start path (`nginx.py:57`, `refxrootd.py:73`,
`dedicated.py`) — the two fleet generations of §2.6 carry two
readiness systems, and the *modern* one is the shallower.
`ServerEndpoint` (9 fields, §5.3) already exists and is genuinely good
— tests consume endpoints, not addresses.

**Designed surface (parity).** Alias strings keep working verbatim —
the whole set, the collapse-to-TCP, the 10 s deadline, and the
start-time `ValueError` are all preserved (strict registration-time
checking is F1's additive mode); internally each alias parses to a
probe object. `SKIP_XRDFS_CHECK` becomes a settings field with env
fallback on the legacy path it belongs to. `ServerEndpoint` moves
as-is.

**Designed additions (additive).**
- The `Probe` family as public API — declared on the spec, executed by
  the backend (§8.4 rule 3; the K8sBackend translates them to
  `readinessProbe`, §8.3):

  ```python
  @dataclass(frozen=True)
  class TcpProbe:                 # the parity default behind every alias
      port_role: str = "primary"  # or a named extra-port
      timeout: float = 10.0       # today's measured deadline, kept

  @dataclass(frozen=True)
  class CommandProbe:             # what xrdfs readiness actually is
      argv: tuple[str, ...]
      timeout: float

  @dataclass(frozen=True)
  class AllOf:
      probes: tuple[TcpProbe | CommandProbe, ...]
  ```

  `CommandProbe` closes a *measured* gap, not a hypothetical one:
  registry-native specs today cannot express protocol-level readiness
  at all — the aliases are cosmetic and only the legacy `lib_py` path
  ever runs `xrdfs`. Post-move, `readiness="root"` can mean what it
  says.
- `Endpoint.url(scheme)` helpers so URL assembly stops being per-suite
  string formatting.

**Failure modes.** `ReadinessTimeout(spec, probe, elapsed, log_tail)` —
today an assertion or a generic launcher error.

**Triad.** tcp + command probes pass against a live stub · timeout
produces `ReadinessTimeout` carrying the instance's log tail ·
security-negative: a probe never runs against a host outside the spec's
declared host (no probe-driven SSRF into non-lane targets).

**Home.** Core.

---

#### F5 — The declaration gate

**Definition.** A test states which servers it uses; the framework
verifies the statement statically and boots only what the selected
tests declared. Selection cost is proportional to what you run, not to
what exists.

**Grown today** (read off `fleet_declares.py`, 416 LOC): the gate is
the suite's most sophisticated grown feature — usage is resolved
through **four detection channels**: (1) explicit
`@pytest.mark.registry_server("name")` / `registry_servers(...)`
markers, (2) fixture reachability, including the conftest fixture map
and autouse fixtures, (3) port-constant bindings — importing
`NGINX_GSI_PORT` binds you to the spec that owns it (`_settings_bindings`
→ `_const_specs`), and (4) an always-on backbone set. Results feed both
enforcement (undeclared use fails the test) and subset boot
(`_specs_to_boot`), with a persistent `config.cache` layer and gw0-only
writes. None of this is written down anywhere except the code; the
channels' interaction is folklore.

**Designed surface (parity).** `brixtest.fleet.declares` +
`brixtest.harness.gate` (core — the mechanism is fully generic: it
resolves *names*, the adapter supplies what names exist). All four
channels, the cache keying, and the gw0-only write rule move verbatim;
the existing declare-cache unit quartet pins them (§11 TS-2 item 2).

Measured cache mechanics (conftest_part3, the history-§11 layer): each
test file is keyed by `(st_mtime_ns, st_size)`; a cache entry stores
`{stamp, usage rows, autouse rows}` per file; writes are batched behind
a dirty flag and flushed once per session, from gw0 only. And the gate
is the one grown feature whose *internals* already look designed —
`fleet_declares.py` exports a clean functional surface that promotes
as-is:

```python
DECLARE_MARKERS = ("registry_server", "registry_servers")
def analyze_source(source: str) -> list[TestUsage]     # AST, no imports
class TestUsage:      # name, lineno; .undeclared() -> set[str]
def conftest_fixture_spec_map(source) -> dict[str, frozenset[str]]
def module_autouse_specs(source) -> frozenset[str]
def backbone_specs() -> frozenset[str]
```

What it lacks is not shape but a *home* and a *document* — which is
exactly what parity plus the how-to supply.

**Designed additions (additive).**
- The four channels become the **documented declaration contract** —
  the how-to (§7.5 docs plan) teaches them; the folklore ends.
- Gate modes `enforce | warn | off` as a settings field (today:
  enforcement is unconditional; `warn` is what a new consumer adopts
  first).
- `brixtest gate explain <test-file>` (F14): per-test resolved specs
  *with channel provenance* — "this test needs `ref-gsi` because it
  imports `REF_BRIX_GSI_PORT`" — turning gate violations from
  archaeology into a one-command answer.
- Cache schema versioning (a stamp in the key) so a gate-logic change
  invalidates cleanly instead of mysteriously.

**Failure modes.** `GateViolation` — message must name the test id, the
undeclared spec, and the cheapest channel that would declare it.

**Triad.** Declared subset boots exactly the declared closure · the
existing gate-negative (undeclared server use) still fails post-move
(the §11 TS-2 security-negative) · security-negative: cache poisoning —
a stale cache entry for a since-edited file is detected by its hash key
and re-scanned, never trusted.

**Home.** Core.

---

#### F6 — Stability machinery

**Definition.** The framework watches its own fleet: a dead fleet
aborts the session loudly; every process is accounted for before and
after; nothing is ever killed that the lane does not own.

**Grown today.** `conftest_part4` (536 LOC, §5.1): sentinel watchdog
(six bare `BRIX_FLEET_SENTINEL*` env knobs), before/after conservation
snapshot, startup-stability window, orphan reaper. The ownership rule
exists because of a real incident — one lane's reaper SIGTERMed every
lane whose root merely started with its own (history §10) — but lives
as code comments, not contract.

The measured knobs and semantics (conftest_part4) — the
`StabilityPolicy` fields inherit these values exactly:

| Knob | Default | Measured meaning |
|---|---|---|
| `BRIX_FLEET_SENTINEL` | on (`0` disables) | master enable |
| poll | 2.0 s | check cadence — piggybacked on per-test hooks, no sleeps, no threads |
| grace | 8 s | a server must stay dead this long to count as damaged; restart windows never trip it |
| min_down | 8 | minimum dead-spec count before the fraction rule applies |
| fraction | 0.5 | fleet fraction treated as catastrophic collapse |
| hard abort | off (`BRIX_FLEET_SENTINEL_ABORT=1`) | abort-the-run vs banner-and-fail |
| `TEST_FLEET_STABILITY_SECS` | 5 s | startup-stability window |

The grown *semantics* here are excellent and need no redesign: the
watchdog is restart-aware (each baseline server is checked via its
**current** pidfile pid, so a test restarting its own subject server
never trips it) and attribution-first (the first confirmed death
aborts with a banner naming the culprit test and pointing at
`$TEST_ROOT/kill-diag.log`). What is grown is the *packaging* — six
module constants read at import. Parity moves the packaging and keeps
the semantics byte-identical.

**Designed surface (parity).** `brixtest.harness.sentinel` +
`brixtest.fleet.orphans` (core), moved verbatim (§11 TS-2 item 3); the
six knobs become a `StabilityPolicy` dataclass (poll, grace, fraction,
min_down, abort) held by `SuiteSettings`, env fallbacks intact (§5.8).

**Designed additions (additive).**
- `owns()` promoted to documented public API with the lane-identity
  rules stated (exact-root match, port-range membership, pidfile
  provenance) — the history-§10 fix as contract, not comment.
- Sentinel trips and conservation results emitted as F15 events; a
  conservation *failure* additionally writes a JSON report (baseline,
  final, delta, suspect pids) under the lane's log dir for post-mortem.
- **Selective-boot aware (as built):** `FleetSentinel.start(watch=…)`
  watches the *booted* set the harness passes, never the whole
  catalogue — under selective boot a catalogued-but-unstarted server
  is not a corpse. (Found by drill: a file booting nothing had the
  sentinel declare the unbooted fleet dead.) `watch=None` — the CLI's
  start-everything path — still means the whole catalogue.

**Failure modes.** `FleetDiedError(dead_specs, at)`,
`ConservationError(delta)`, `LaneOwnershipError(path, owner)`.

**Triad.** Watchdog aborts a session whose critical spec is killed
mid-run (existing test) · conservation flags one leaked listener with
its pid and port · security-negative: the reaper presented with a
foreign lane's process (same prefix, different root) refuses — the
history-§10 regression test, permanent.

**Home.** Core.

---

#### F7 — Artifact pipeline with snapshot caching

**Definition.** Expensive prerequisites (PKI, tokens, keytabs) are a
DAG of declared steps with sentinel-verified outputs and a
content-addressed, TTL'd, generator-stamped cross-session cache.

**Grown today.** `fleet_prep.py` (322 LOC): an imperative `prepare()`
sequence (PKI → JWKS → signing key → fleet artifacts → issued JWTs →
CRLs → authdb → stage hook) with sentinel files, plus the snapshot
cache that took warm prep from 11.3 s to 0.03 s (history §11). Cache
TTL, location, and the `BRIX_FLEET_PREP_CACHE` kill-switch are module
constants/env reads; the step list is a function body, so "what will
prep do" has no answer short of reading it.

Measured decision structure (fleet_prep.py): `_CACHE_VERSION = 1`,
TTL `4 * 3600` s — deliberately bounded by the shortest-lived artifact
in the set (12 h proxies). A snapshot restore is rejected on exactly
**four enumerable grounds**: generator stamps mismatch against
`_generator_stamps()`, age ≥ TTL, corrupt/unreadable metadata, or a
copy error mid-restore — every rejection falls back to generate.
Warn-and-continue upstream generator failures are made visible by
per-tolerated-generator sentinel files inside the snapshot, so a
cached snapshot can never silently launder a half-built artifact set.

**Designed surface (parity).** The `FleetPrep` engine of §9.2.4 (core)
with the steps supplied by `brix_suite.prep_steps` (adapter);
module-level `prepare()` wrapper preserved; cache semantics — key
inputs, TTL, generator-source stamping, the never-inside-the-
destructible-tree rule — unchanged and pinned by
`test_fleet_prep_cache.py`.

**Designed additions (additive).**
- `PrepStep` protocol (`name`, `sentinels`, `generate(settings)`) — a
  consumer's pipeline is a list of these, and the engine owns ordering,
  verification, and caching.
- `brixtest prep --explain` (F14): the step list, each step's sentinel
  state, and the restore-vs-generate decision with its reason. The
  decision vocabulary is *already in the code* — the four measured
  rejection grounds above — so `--explain` prints which one fired
  rather than inventing a new taxonomy.
- `ArtifactSet` — a manifest (name → path + role: `secret | public |
  config`) produced by the pipeline; the K8sBackend consumes it to
  materialize Secrets/ConfigMaps (§8.3). Locally it is documentation;
  in-cluster it is the deployment input.

**Failure modes.** `PrepStepError(step, cause)`; cache corruption is
*never* fatal — restore failure falls back to generate (today's
behavior, now stated as a guarantee).

**Triad.** Cold generate → warm restore round trip (existing quartet) ·
a step whose sentinel is missing post-generate raises `PrepStepError`
naming the step · security-negative: a snapshot whose generator stamp
mismatches current sources is discarded, not restored (stale-crypto
guard, existing test).

**Home.** Engine core; steps adapter.

---

#### F8 — Lanes and the port ledger

**Definition.** A lane — `(root, port_base)` — is the unit of
isolation. Two distinct lanes on one host never interact: not through
ports, not through paths, not through `/tmp`, not through reapers.

**Grown today.** The `TEST_ROOT` + `TEST_PORT_START` env contract
(§2.4), the TMPDIR pin (§5.10), the foreign-lane refusal message, 178
named fixed-port constants + `port_ladder` dynamic ranges (Appendix D).
It all works — but the lane exists only as a convention spread across
settings, conftest, and the reaper; nothing can *tell you* about a
lane.

The grown shape in one API: `port_ladder`'s public surface is
**namespace mutation** — `rebase_settings(namespace)`,
`rebase_named_ports(ports, category=...)`,
`rebase_lifecycle_ledger(ledger, shared=...)`, `rebase_cmdscripts(blocks)`
each rewrite a caller's module dict in place. That is *why* lane math
is untestable without module reloads (§2.4), and it is the cleanest
single exhibit of grown-vs-designed in the suite: the designed
`PortLedger` computes the same numbers from the same inputs and
mutates nothing outside the §10.2 shim.

**Designed surface (parity).** `brixtest.config.lanes.Lane` +
`brixtest.config.ports.PortLedger` per §9.2.1 (core machinery; the 178
named constants stay adapter data): identical lane math, byte-identical
refusal message, `TEST_<NAME>` overrides preserved mechanically,
`iter_named_ports()` for the guard (§12).

**Designed additions (additive).**
- `Lane.current()` and an on-disk ownership record making refusal
  messages precise — *which* session owns the lane, since when, and
  whether it is still alive:

  ```json
  { "lane_root": "/tmp/xrd-test-migration-lane", "port_base": 23000,
    "pid": 41213, "session": "<uuid4>", "hostname": "…",
    "started_at": "2026-08-17T14:02:11Z" }
  ```

  Written at session start, removed at session end, consulted by the
  reaper (F6) and by `lane status` before any destructive act.
- `brixtest lane status` (F14): listeners inside the lane's port
  ranges, which spec each belongs to, foreign occupants flagged.
- The non-interaction guarantee written as contract: distinct
  `(root, port_base)` lanes share no state; every destructive operation
  (wipe, reap, kill) checks lane identity first (F6's ownership rules).

**Failure modes.** `LaneOwnershipError`, `PortCollisionError(port,
holder_spec, foreign_pid)`.

**Triad.** Two lanes with distinct bases run the §14 gate concurrently,
zero cross-talk (the soak already does this implicitly; the test makes
it explicit) · malformed `TEST_PORT_START` fails exactly as today (§11
TS-3 error test) · security-negative: the foreign-lane refusal fires
against a live foreign fleet (existing test, re-run through the shim).

**Home.** Core machinery, adapter data.

---

#### F9 — Deployment backends

**Definition.** Where instances *run* is a strategy object. Specs,
kinds, plans, probes, lanes, and the gate never know.

The full specification is §8 (interface §8.1, `LocalBackend` guarantees
§8.2, `K8sBackend` mapping §8.3, core rules §8.4). As a feature: parity
is the seam-cut plus `LocalBackend` (TS-4, behavior-identical); the
additive tail is `brixtest.testing.backend_contract` — a conformance
suite both backends must pass, giving TS-9 its acceptance shape ("the
SAME test file passes against both backends"). Its cases, enumerable
now because they are the §8.1 protocol read as obligations: the full
prepare → start → endpoint → is_ready → logs → stop round trip;
endpoint stability across repeated `is_ready` polls; a bad spec
surfacing as the F3/F4 taxonomy (never a backend-native error);
`process_snapshot` accounting for every started instance and nothing
else; stop leaving the snapshot clean; and probes executed *by the
backend*, never by the caller. Failure modes:
`BackendError` wrapping backend-specific causes; a backend must
translate its native failures (exec error, pod pending) into the F3/F4
taxonomy so tests see one vocabulary.

**Home.** Interface + `LocalBackend` core; `K8sBackend` future (TS-9).

---

#### F10 — The pytest plugin and fixture surface

**Definition.** BriXTest meets pytest at exactly one point: a named
plugin owning the session lifecycle, the gate hooks, and a versioned
fixture family. Everything the plugin does is also callable as a plain
library.

**Grown today.** Nine hooks and 15 fixtures spread across five exec'd
conftest files (§5.1); ordering constraints that live in comments;
marker registration split across two homes (§5.9); the harness testable
only via a by-path second copy of itself (§2.5).

**Designed surface (parity).** `brixtest.harness.plugin` per §9.2.5:
every hook a one-line delegation, ordering invariants unit-tested,
worker/collectonly gates first-statements-by-test, marker registration
consolidated, the 15-fixture table of §5.1 byte-compatible. Activation
via `pytest_plugins` with the `pytest11` entry point disabled until
soak (R9).

**Designed additions (additive).**
- The fixture/hook table becomes the **versioned public surface**: a
  fixture rename or scope change is a major version bump (§7.5 API
  policy). Today the surface is whatever tests happen to import.
- The plugin takes an explicit adapter-configuration object — the one
  place a consumer wires their suite in (today the equivalent wiring is
  implicit in import side effects across the five conftest shards):

  ```python
  @dataclass(frozen=True)
  class HarnessConfig:
      settings: SuiteSettings
      register_catalogue: Callable[[], None]   # fills the F1 registry
      kinds: Sequence[KindProfile]             # F2 rows
      prep_steps: Sequence[PrepStep]           # F7 pipeline
      extra_fixtures: str | None = None        # adapter plugin module
  ```
- Double-activation (entry point + conftest) detected and refused with
  a message naming both registration paths (the §11 TS-2 error test).
- `file_linear: bool = True` (as-built): each file's tests are one
  ordered stream. Serially that is just collection order; under xdist
  the plugin's `pytest_xdist_make_scheduler` upgrades the *implicit*
  `--dist load` default to `loadfile` scheduling, pinning a file's
  tests to one worker in file order (§7.13 vii). An **explicit**
  operator dist choice (`--dist worksteal`, …) always wins — the knob
  changes the default, never overrides a human.

**Failure modes.** `PluginActivationError`.

**Triad.** Full harness pinning suite (67 tests, §5.10) green through
shims · double-activation refused · security-negative: a worker process
(`workerinput` present) can never execute the destructive session-setup
path — pinned as a test, not a comment.

**Home.** Core; suite fixtures (`ref_xrootd`, mu family) adapter.

---

#### F11 — Crash-isolated client drivers

**Definition.** Native client libraries run in disposable worker
processes speaking a framed request/response protocol under a
wall-clock deadline. A wedged or crashed client library costs one
worker, never the runner.

**Grown today** (measured). `_xrdcl_worker.py` (400 LOC) spawned **by
file path** (R10) with `_xrdcl_proxy` as the in-runner side. The
protocol is JSON lines over stdin/stdout: each request is one
`json.dumps` line carrying a tag; the worker serializes XrdCl results
into JSON-safe structures and writes tagged response lines **in
completion order** through a line-buffered stdout under a writer lock.
The runner side is `call(req, timeout=_CALL_TIMEOUT)` with
`_CALL_TIMEOUT = float(env XRDCL_PROXY_TIMEOUT, default 90 s)`; on
expiry the worker is killed — which is why `timeout_method = signal`
is safe at all (§5.9). It is a real protocol with real concurrency
discipline — implicit in two files, reusable by nothing.

**Designed surface (parity).** `brixtest.clients.procworker` (core —
the protocol and lifecycle) + `brix_suite.clients` (the XrdCl
specifics); spawn switches to `python -m` one call-site at a time (§11
TS-5, both-forms test). Behavior — framing, deadline, kill — identical.

**Designed additions (additive).**
- The `ProcWorker` protocol documented — the measured framing above,
  written down and versioned. The designed frame is the measured frame
  plus a structured error object:

  | Frame | Fields |
  |---|---|
  | request | `tag` (caller-unique) · `op` · op-specific args |
  | response (ok) | `tag` · `ok: true` · `result` (JSON-safe) |
  | response (err) | `tag` · `ok: false` · `error{type, message, stderr_tail}` |

  Delivery stays completion-order (tags, not sequencing, correlate);
  deadline semantics, TERM→KILL escalation timing, and a structured
  crash report (exit code, signal, stderr tail) replace today's bare
  timeout.
- An adapter-side registry of callables the worker will execute, so a
  second consumer isolates *their* native library with zero new
  process code.

**Failure modes.** `WorkerTimeout(deadline, request)`,
`WorkerCrash(rc, signal, stderr_tail)`.

**Triad.** Round-trip call through a worker · a worker that sleeps past
deadline is killed and reported as `WorkerTimeout` with the runner
unharmed · security-negative: a worker inherits the lane's confined
TMPDIR and cannot write outside the lane tree.

**Home.** Protocol core; XrdCl/HTTP/gridftp drivers adapter; `cli_pty`
promotes.

---

#### F12 — The stub server library

**Definition.** Small, single-purpose counterpart servers (the "other
side" a test needs: an OCSP responder, an OIDC endpoint, a misbehaving
origin) with uniform startup, binding, readiness, and logging.

**Grown today.** Eight scripts in `tests/lib/` (Appendix C), each with
its own arg/env parsing, each spawned by path via `proc` specs. They
work; they share nothing. The measured inventory — each one a
counterpart some protocol test cannot run without:

| Stub | Plays the role of |
|---|---|
| `ocsp_responder.py` | CA-side OCSP responder for revocation-path tests |
| `fwd_oidc_server.py` | OIDC provider for token-forwarding flows |
| `introspect_idp_server.py` | token-introspection IdP |
| `static_origin_server.py` | plain HTTP origin behind cache/proxy paths |
| `mirror_shadow_server.py` | shadow origin for mirror-divergence tests |
| `guard_stub_server.py` | in-suite guard endpoint |
| `fwd_mint_proxy.py` | proxy-credential-minting forwarder |
| `tokenconf.py` | WLCG token-conformance server |

**Designed surface (parity).** One-to-one moves to
`brix_suite.servers.*`, `-m` spawn, one spec per commit (§11 TS-5).

**Designed additions (additive).** A shared `StubServer` base:
bind-address and port taken from the spec-provided environment, refusal
to bind outside the lane (the TS-5 security-negative, promoted to base-
class behavior), uniform readiness signaling, and a common access-log
line format the F15 event stream can ingest.

**Failure modes.** Refusal-to-bind exits non-zero with a one-line
reason (specs surface it via F3's `StartError` log tail).

**Triad.** Each stub starts/serves/stops under its spec · bad bind
config exits non-zero with the reason · security-negative: a stub asked
to bind outside the lane root refuses (no bare-`/tmp` listeners).

**Home.** Adapter (the stubs are protocol-specific); the base class is
a core promotion candidate once a second consumer exists (§7.2 rule).

---

#### F13 — Config templating

**Definition.** Instance configs are rendered from a manifest of
templates with values assembled from settings + spec + endpoint; every
placeholder is accounted for.

**Grown today.** `render_cfg` (measured, `lib_py/util.py:26`) is
literal `{key}` string replacement — not `str.format`, so unknown
braces pass through silently; 541 templates (§2.7) with values
assembled by `_session_values` + `_endpoint_template_values` (mixinc)
and the `REGISTRY_STRICT_TEMPLATES` knob; `check_template_refs.py`
partially guards references. An unresolved placeholder today becomes a
syntactically odd config the server then rejects — the failure surfaces
two steps downstream of its cause.

And there is a measured **second template system**: `matrix_layer`
builds nginx config *fragments* programmatically, parameterized by
`Cell(protocol, auth, tls, backend)` — a `__slots__` value object
whose `id` (`"root-gsi-tls-posix"` style) is exactly what appears in
the pytest report — with `supported(cell)` pruning and
`expand(protocols, auths, tls, backends)` enumerating the lattice —
over the measured vocabulary `PROTOCOLS = ("root", "webdav", "s3")`,
`AUTHS = ("none", "gsi", "token", "sigv4")`, with streaming confined
to `("root",)`. Two template systems, one file-based and one
programmatic, share no manifest and no provenance.

**Designed surface (parity).** Rendering semantics byte-identical
(literal replacement, same value assembly, same knob); templates
resolved through `asset()` from TS-6 (§9.2.7); rendered bytes unchanged.

**Designed additions (additive).**
- Template manifest completeness both ways (guard #5, §12): every
  reference exists, every template is referenced or whitelisted.
- Strict mode gains an unresolved-placeholder scan at render time:
  `TemplateError(template, missing_keys)` at the *cause*, not two steps
  later. Default-off until the whitelist of deliberate literal braces
  (nginx's own `{}` blocks) is inventoried at TS-6.
- Render provenance (template path, values digest) recorded in the F15
  run report — never written into the rendered file itself (rendered
  bytes stay identical; NG2).
- The matrix layer's fragments join the same pipeline: `Cell` stays the
  coordinate vocabulary (its pytest-visible `id` is a de-facto public
  interface and is preserved verbatim), but fragment renders gain the
  same provenance record as file templates — one manifest covering
  both systems instead of neither.

**Failure modes.** `TemplateError(template, missing_keys)` (strict,
additive).

**Triad.** Render round trip vs golden bytes · strict-mode missing key
raises naming template and keys · security-negative: template values
containing path traversal (`../`) into another lane are refused by the
`asset()` resolver.

**Home.** Mechanism core (`brixtest.util.configtext`); templates and
value policy adapter.

---

#### F14 — The operations CLI

**Definition.** One entry point, `brixtest`, whose verbs operate on
whatever catalogue the adapter registers, with contractual exit codes
and machine-readable output.

**Grown today.** `python3 -m cmdscripts.manage_test_servers` — five
verbs, cwd-dependent identity (§2.1), plus a top-level tombstone module
(§5.4) and 143 scenario scripts. Output is for eyes only; exit codes
are incidental.

**Designed surface (parity).** §9.2.6: the `brixtest` entry point with
`fleet start-all|stop-all|restart|status|start-dedicated`, `prep`,
`run`; the `python -m cmdscripts.…` form kept working via forwarder
(identical `status` output pinned by test); the tombstone keeps failing
loudly (Appendix A).

**Designed additions (additive).**
- Exit-code contract: 0 success · 1 operational failure (a spec failed,
  a lane refused) · 2 usage error. CI stops parsing stdout to learn
  what happened.
- `--json` on `status` and `plan` (schema = serialized F1 specs + F3
  report + F15 events; versioned with the package).
- The diagnostic verbs the designed features enable: `lane status`
  (F8), `gate explain` (F5), `prep --explain` (F7), `fleet plan` (F3) —
  each one replaces a today-folklore debugging ritual with a command.

The verb surface in one table (parity verbs first, diagnostic verbs
below the rule):

| Verb | Source | Exit codes | `--json` payload |
|---|---|---|---|
| `fleet start-all` / `stop-all` / `restart` / `status` / `start-dedicated` | parity: `manage_test_servers` | 0/1/2 | `status`: specs + F3 `SpecOutcome`s |
| `prep` | parity: `fleet_prep.prepare()` | 0/1/2 | steps + restore/generate decisions |
| `run` | parity: pytest passthrough with lane env applied | pytest's own | — |
| `fleet plan` | new (F3) | 0/1/2 | serialized `FleetPlan` |
| `lane status` | new (F8) | 0/1/2 | listeners, owning specs, foreign occupants, ownership record |
| `gate explain <file>` | new (F5) | 0/1/2 | per-test resolved specs with channel provenance |
| `prep --explain` | new (F7) | 0/1/2 | per-step sentinel state + which of the four grounds fired |
| `map [paths…] [--run ID] [--mermaid]` | new (F5/F21, as built) | 0/1/2 | test↔server rows — declared (gate closure over files, no runtime) or observed (`--run`, store rows incl. dynamic counts); ASCII matrix or Mermaid graph |

What the diagnostic verbs look like — non-normative exemplars (the
`--json` schema binds; the prose layout does not):

```console
$ brixtest lane status
lane /tmp/xrd-test-migration-lane   ports 23000–23999
  owner pid 41213 session 9f31c2e8 started 2026-08-17T11:02:44Z (alive)
  38 listeners, all owned:
    23080  ref-anon   (nginx)   ready 2h11m
    23112  ref-gsi    (nginx)   ready 2h11m
    …
  foreign occupants: none

$ brixtest gate explain tests/test_tpc_delegation.py
tests/test_tpc_delegation.py::test_pull_delegated
  ref-gsi     marker    @pytest.mark.registry_server("ref-gsi")
  tpc-target  port      imports REF_TPC_TARGET_PORT (settings binding)
  main        backbone  always-on set

$ brixtest fleet plan
level 0: main  ref-anon  ref-gsi  tpc-target     (workers: 16)
level 1: webdav-proxy
2 levels · 5 specs · backend local · lane /tmp/xrd-test-migration-lane
```

Every line above is assembled from objects §7.3 already specifies —
the ownership record, the F5 channel provenance, the `FleetPlan` — so
the transcripts are renderings, not new features.

**Failure modes.** Usage errors exit 2 with the offending argument;
operational errors render the underlying taxonomy exception (§7.5) and
exit 1.

**Triad.** Both invocation forms produce identical `status` ·
unknown verb exits 2 · security-negative: `stop-all` in a lane it does
not own refuses (F8 ownership) instead of killing.

**Home.** Core; verbs act on adapter-registered catalogue.

---

#### F15 — Run observability (new; additive-only)

**Definition.** Every significant lifecycle event of a session — spec
started/ready/stopped/failed, gate decisions, sentinel trips,
conservation results, prep restore/generate — is one line of
structured, append-only JSONL under the lane's log dir.

**Grown today.** This feature has no grown counterpart — which is
itself the finding: today's answer to "what happened in that run" is
scattered across pytest output, per-instance log files, the kill
tracer, and terminal summaries, each with its own format. Debugging a
red fleet is archaeology (§5.1's kill-diag exists *because* of this).

**Designed surface.** Entirely additive (no parity component, no test
behavior change — a write-only artifact): an `Event(ts, kind, spec,
lane, data)` record; emitters in the launcher (F3), gate (F5), sentinel
(F6), and prep (F7); consumers are `brixtest fleet status --json`
(F14), the terminal summary, and humans with `jq`. Schema is **v0 /
explicitly unstable** until TS-8 (§15). The skeleton (record type +
launcher emitter) lands with TS-4, gated separately from the parity
commits.

The v0 event-kind catalogue (each kind's `data` payload reuses the
emitting feature's existing structures — no new vocabulary):

| Kind | Emitter | `data` |
|---|---|---|
| `spec.start` / `spec.ready` / `spec.stop` / `spec.fail` | F3 | `SpecOutcome` fields: result, elapsed, log path |
| `gate.enforce` / `gate.violation` | F5 | test id, resolved specs, channel provenance |
| `sentinel.trip` | F6 | dead specs, culprit test, kill-diag path |
| `conservation.ok` / `conservation.fail` | F6 | baseline/final delta, suspect pids |
| `prep.restore` / `prep.generate` | F7 | per-step decision + which of the four grounds fired |
| `lane.acquire` / `lane.release` / `lane.refuse` | F8 | the ownership record |

One line, concretely (v0 exemplar):

```json
{"ts": "2026-08-17T11:02:51.407Z", "kind": "spec.ready",
 "spec": "ref-gsi", "lane": "/tmp/xrd-test-migration-lane",
 "data": {"elapsed": 1.84, "probe": "tcp:23112",
          "log": "logs/ref-gsi/error.log"}}
```

**Failure modes.** Event emission must never fail a run: emitter errors
are swallowed to a fallback line in the instance log (observability
cannot become a new failure mode).

**Triad.** A gate-through-stop session yields a well-formed event
stream · an unwritable log dir degrades to fallback without failing the
run · security-negative: event `data` never contains credential
material (token/key bytes are logged as digests — pinned by test).

**Home.** Core.

### 7.4 How this addresses the server↔client testing needs

The needs ledger of §4.2, restated as the framework's requirements
traceability (need → feature spec → where it lives). Every need is
covered by at least one F-spec; every F-spec except the purely
ergonomic F14/F15 traces back to a need:

| # | Need (server↔client) | Feature specs | BriXTest answer | Home |
|---|---|---|---|---|
| 1 | Thousands of tests share long-lived servers | F1, F3, F5, F10 | declarative fleet + session lifecycle + declaration-gated subset boot | `brixtest.fleet`, `brixtest.harness.gate` |
| 2 | One owner for destructive lifecycle under xdist | F10 | controller-only session ownership, worker gating preserved verbatim | `brixtest.harness.session` |
| 3 | Mid-run fleet death must abort loudly | F6 | sentinel watchdog + conservation check | `brixtest.harness.sentinel` |
| 4 | Real credentials, cheap re-runs | F7 | artifact pipeline + snapshot cache engine; recipes stay adapter-side | `brixtest.fleet.prep` / `brix_suite.security` |
| 5 | Concurrent lanes must not collide or reap each other | F8, F6 | `Lane` + `PortLedger` + ownership-checked reaping | `brixtest.config` |
| 6 | Native client crashes must not kill the runner | F11 | out-of-process worker driver | `brixtest.clients` |
| 7 | No orphaned listeners after aborts | F6, F8 | orphan reaper + kill tracer + `owns()` | `brixtest.fleet.orphans` |
| 8 | Hundreds of config permutations | F2, F13, F1 | kind profiles + template render + matrix layer + spec catalogue | core mechanism / adapter data |
| — | Servers/clients need counterpart endpoints | F12, F4 | stub server library + probes/endpoints | adapter / core |
| — | Humans and CI need to see and drive the fleet | F14, F15 | CLI verbs with exit-code/JSON contracts + event stream | core |

### 7.5 Cross-cutting design contracts

Seven contracts apply to every feature. They are what separates a
designed framework from a grown one at the texture level — the places
where organic code says "it depends" and designed code has one answer.

**C1 — The error taxonomy.** One base, `BrixTestError`, with the
feature-owned exceptions of §7.3 beneath it (`SpecError`,
`RegistrationError`, `UnknownKindError`, `StartError` ⊃
`RegistryCommandFailure`, `QuiescenceError`, `ReadinessTimeout`,
`GateViolation`, `FleetDiedError`, `ConservationError`,
`LaneOwnershipError`, `PortCollisionError`, `PrepStepError`,
`PluginActivationError`, `WorkerTimeout`, `WorkerCrash`,
`TemplateError`, `BackendError`). The grown tree has exactly one
designed exception today — `RegistryCommandFailure`
(`server_launcher_errors.py`: a dataclass carrying command, returncode,
config path, logs dir, and stdout/stderr tails) — and it is the model:
**every** taxonomy exception carries the structured fields its handler
needs, and every user-facing failure message names (a) the lane, (b)
the spec or step involved, and (c) the next command to run (`gate
explain`, `lane status`, the log path). Bare `RuntimeError("...")` in
core is a review blocker from TS-2 onward; existing grown raises
convert opportunistically as their modules move, preserving exception
*compatibility* via subclassing wherever anything catches them today.

The taxonomy with its structured fields, in one table (fields are the
contract; adding one is minor, removing or renaming one is major, C3):

| Exception | Structured fields | Raised by |
|---|---|---|
| `SpecError` | field, value, violated rule | F1 strict validation |
| `RegistrationError` | spec, conflicting spec/port | F1 registry |
| `UnknownKindError` | kind, known kinds | F2 |
| `StartError` ⊃ `RegistryCommandFailure` | spec, phase, command, returncode, config path, logs dir, stdout/stderr tails | F3 |
| `QuiescenceError` | survivors as (spec, port, pid) | F3 stop |
| `ReadinessTimeout` | spec, probe, elapsed, log tail | F4 |
| `GateViolation` | test id, undeclared spec, cheapest declaring channel | F5 |
| `FleetDiedError` | dead specs, culprit test, kill-diag path | F6 |
| `ConservationError` | delta, suspect pids | F6 |
| `LaneOwnershipError` | path, owner record | F6/F8 |
| `PortCollisionError` | port, holder spec, foreign pid | F8 |
| `PrepStepError` | step, cause | F7 |
| `PluginActivationError` | both registration paths | F10 |
| `WorkerTimeout` | deadline, request op | F11 |
| `WorkerCrash` | exit code, signal, stderr tail | F11 |
| `TemplateError` | template, missing keys | F13 |
| `BackendError` | backend, wrapped cause | F9 |

The message bar, measured against today's own output — because the
grown suite already contains both the best and the worst of it. Two
grown messages **already meet C1** and are canonized as the house
style: the foreign-lane refusal (`conftest.py:504` — names the lane,
the owned port, the rule, the remedy, and what was *not* done: "…is
owned by another or incomplete test fleet. Choose a non-overlapping
TEST_PORT_START; each lane reserves the complete central port ladder.
The foreign listener was not modified.") and the gate report
(`conftest_part3:476` — count, per-test file:line, missing spec names,
and the exact marker to add). Against them, the exemplar of what C1
retires (`mixinc:208`):

```
grown:     RuntimeError: server did not become ready on 127.0.0.1:23112
designed:  ReadinessTimeout: ref-gsi: tcp probe on 127.0.0.1:23112
           unanswered after 10.0s — last log line:
           logs/ref-gsi/error.log:41 'bind() to 0.0.0.0:23112 failed
           (98: Address already in use)' · try: brixtest lane status
```

Same event; the grown message names neither the spec, the probe, the
deadline, the log, nor a next step — and is catchable only as
`RuntimeError`. C1's rule is that the *worse* message is the review
blocker, and the two canonized grown messages are the proof the bar
is reachable, not aspirational.

**C2 — Configuration precedence.** One rule everywhere: **explicit
constructor argument > environment variable > coded default.**
`from_env()` (§9.2.1) is the only environment reader in the package;
every env knob of §5.8 is reachable as a constructor argument, which is
what makes infra unit-testable without `monkeypatch`/`reload` (Appendix
B). Env names are frozen for compatibility (`TEST_*`, `BRIX_*`); new
knobs get a field first and an env spelling second, derived
mechanically from the field name.

**C3 — Public API and versioning.** Each core module declares
`__all__`; the package ships `py.typed` and full annotations (3.9-floor
syntax, R8). The versioned public surface is: the F-spec APIs, the
fixture/hook table (F10), the CLI verbs and their exit codes/JSON
schemas (F14), and the env-name contract (C2). Semver from `0.x`
honestly (breaking allowed, announced) with `1.0` declared when TS-1…
TS-6 have soaked; thereafter a fixture rename, hook reorder, exit-code
change, or event-schema break is a major bump. Deprecations live one
minor release minimum with a `DeprecationWarning` naming the
replacement — the same courtesy the `_legacy` package extends to
bash-era survivors (§11 TS-5).

**C4 — Observability is structured or it is noise.** New diagnostics
go through the F15 event stream, never through bare `print`. The
grown kill tracer and terminal summaries keep working (parity) and
become event consumers over time. Emission failures never fail runs
(F15's own guarantee).

**C5 — The documentation set.** A designed framework ships its manual.
`BriXTest/README.md` (front door, TS-1 stub → TS-8 full), a generated
API reference over `__all__`, this charter as the design record, and
four task-oriented how-tos matching the four things every new consumer
does: *write an instance spec*, *add a kind*, *run in an isolated
lane*, *debug a red fleet* (the last one is `lane status` + `gate
explain` + `fleet plan` + the event stream — the F14 diagnostic verbs
in narrative order). The declaration contract (F5's four channels) gets
its section in the how-tos; the folklore era ends there.

**C6 — Concurrency and ownership.** Every mutable resource names its
single writer. The rules all *exist* today — measured as scattered
guard clauses — and C6 restates them as the design rule new code is
reviewed against:

- Destructive session lifecycle (start-all, stop-all, wipe) is
  **controller-only**: any process with `workerinput` present refuses
  it (F10's pinned security-negative).
- Cross-session caches (declare cache, prep snapshots) are written
  from **gw0 only**; all workers may read.
- Parallel start (F3) is the only intra-framework parallelism; its
  worker count is a settings field, and `1` is always a valid
  sequential fallback.
- The F11 worker serializes all responses through one locked,
  line-buffered stream; concurrency is expressed in tags, never in
  interleaved bytes.
- Cross-*process* coordination happens only through lane-scoped files
  — the ownership record, pidfiles, the fleet-ready marker — never
  through in-memory state and never through any lock shared across
  lanes (the history-§10 incident is the case law).

Anything else that wants to mutate shared state must route through
the feature that owns it, or it does not merge.

**C7 — Nomenclature.** A designed framework has one naming rulebook;
a grown one has whatever each year's author reached for. The rules,
several of them simply canonizing the suite's existing best practice:

- **Spec names**: kebab-case noun phrases (`ref-gsi`, `tpc-target`),
  unique in the registry (F1).
- **Kinds**: lowercase single tokens (`nginx`, `proc`).
- **Event kinds**: dotted lowercase `noun.verb` (`spec.ready`,
  `lane.refuse`) — the F15 catalogue is the closed vocabulary.
- **Env vars**: `TEST_*` for user-facing lane/config knobs, `BRIX_*`
  for framework-behavior knobs; both families frozen (C2), and a new
  knob's env spelling is derived mechanically from its field name.
- **Exceptions**: named for the failure fact, not the module —
  `GateViolation`, `QuiescenceError`, `WorkerTimeout`; never a generic
  `<Module>Error` beside a specific one.
- **Fixtures**: snake_case, versioned by the F10 table.
- **CLI**: `brixtest <noun> <verb>` (`fleet start-all`, `lane
  status`); flags kebab-case.
- **Modules**: singular where a type lives (`registry`), plural for
  collections (`kinds`, `probes`); and no core module name may carry a
  protocol or product spelling — `nginx`/`xrootd`/`wlcg` appear only
  under `brix_suite` (the grep-able companion to guard #8).

### 7.6 The shape delta — grown vs designed, at a glance

| # | Feature | Grown shape (today) | Designed shape (BriXTest) |
|---|---|---|---|
| F1 | Instance model | 15-field dataclass, string-typed, validated on demand, module-global registry, not serializable | validated at registration, serializable, aliased single instance |
| F2 | Kinds | `if kind ==` ladders ×4 methods ×3 files, pidfile literals ×3 | one table row + two callables + exported contract-test kit |
| F3 | Orchestration | plan transient inside a method, outcomes as log lines, env-var knobs | inspectable `FleetPlan`, `StartReport`, defined idempotence, settings fields |
| F4 | Readiness | inline string dispatch, hard-coded timeouts, env skip | `Probe` objects on the spec, backend-executed, settings deadlines |
| F5 | Declaration gate | four detection channels as folklore in 416 LOC | documented contract + `gate explain` provenance + versioned cache |
| F6 | Stability | six bare env knobs, ownership rules in comments | `StabilityPolicy` fields, `owns()` as contract, conservation reports |
| F7 | Artifacts | imperative step sequence, cache constants in module scope | `PrepStep` DAG, `prep --explain`, `ArtifactSet` manifest |
| F8 | Lanes/ports | env-pair convention spread across three modules | `Lane` object, ownership record, `lane status`, written guarantee |
| F9 | Deployment | fork/exec fused into the launcher | `DeployBackend` strategy; local now, k8s later, one conformance suite |
| F10 | pytest surface | 9 hooks + 15 fixtures across five exec'd files, ordering in comments | named plugin, versioned fixture table, tested ordering, one config object |
| F11 | Client isolation | two files speaking an implicit protocol, spawned by path | documented `ProcWorker` protocol, `-m` spawn, structured crash reports |
| F12 | Stubs | eight scripts sharing nothing | common base: lane-bound binding, uniform readiness + logging |
| F13 | Templating | literal `{key}` replace, silent unresolved placeholders | manifest-guarded, strict-mode `TemplateError` at the cause |
| F14 | CLI | cwd-dependent module, eyes-only output, incidental exit codes | entry point, exit-code contract, `--json`, diagnostic verbs |
| F15 | Observability | scattered prints/logs/summaries; debugging is archaeology | append-only JSONL event stream, versioned schema, `jq`-able |

### 7.7 How the features compose — and what a second consumer writes

The fifteen specs are not a list; they are a dependency structure, and
the structure is what makes the framework claim honest:

```
F8 lanes ────┬──► F3 orchestration ──► F9 backends
F1 specs ────┤         ▲    ▲
F2 kinds ────┘         │    │
F4 probes ─────────────┘    │
F7 artifacts ───────────────┘  (prepare() before start)
F5 gate ──► F3 (subset boot: gate output is the start set)
F6 stability ──► F3/F8 (ownership + conservation over the fleet)
F10 plugin = session-scoped composition of F3+F5+F6+F7+F8
F11 clients / F12 stubs = the other side of the wire, spec-launched
F13 templating ──► F2 (kind renderers consume it)
F14 CLI / F15 events: read everything, own nothing
```

Genericity (§7.2) is best demonstrated, not asserted. Here is the
*complete* wiring a hypothetical second consumer writes to test `kvd`,
a key-value daemon with a replica — every line adapter-side, nothing
nginx-flavored imported anywhere:

```python
# acme_suite/kinds.py
KVD = KindProfile(kind="kvd", pidfile="run/kvd.pid",
                  stop="signal-pidfile", starter=start_kvd,
                  renderer=render_kvd_conf)          # F2, F13

# acme_suite/catalogue.py
def register_catalogue() -> None:                    # F1
    register(InstanceSpec(name="kv-a", kind="kvd", port=25100,
                          template="kvd/basic.conf.tpl",
                          readiness="tcp"))
    register(InstanceSpec(name="kv-b", kind="kvd", port=25101,
                          template="kvd/replica.conf.tpl",
                          requires=("kv-a",), readiness="tcp"))

# acme_suite/prep_steps.py
class SharedSecret:                                  # F7
    name, sentinels = "shared-secret", ("secrets/kv.key",)
    def generate(self, settings): write_key(settings.artifact_root)

# tests/conftest.py
pytest_plugins = ["brixtest.harness.plugin"]         # F10
def pytest_configure(config):
    activate(HarnessConfig(settings=SuiteSettings.from_env(),
                           register_catalogue=register_catalogue,
                           kinds=[KVD], prep_steps=[SharedSecret()]))

# tests/test_replication.py
@pytest.mark.registry_servers("kv-a", "kv-b")        # F5
def test_replica_follows(fleet):                     # F10 fixture
    a, b = fleet.endpoint("kv-a"), fleet.endpoint("kv-b")   # F4
    put(a, "k", "v"); assert get(b, "k") == "v"
```

Lanes, ports, parallel start, the declaration gate, sentinel,
conservation, orphan reaping, prep caching, CLI verbs, and the event
stream all apply to `kvd` with zero additional code — that is the
core/adapter split earning its keep. This example (or one like it)
becomes an executable fixture in `brixtest`'s own test suite at TS-8:
the genericity guard that CI runs, not prose.

### 7.8 The same debugging session, before and after

The texture argument of §7.5, made concrete. *Scenario: you start a
session and the fleet is red.*

**Today.** Read the pytest banner; know that the real reason is in one
of `$TEST_ROOT/logs/*/`; know which pidfile each kind writes (three
hard-coded spellings, F2) to check what is actually alive; run `ss`
by hand and map listeners back to specs via the 178 port constants in
your head; consider whether another lane's reaper took you out
(history §10) or whether a stale snapshot poisoned prep — neither is
recorded anywhere. Every step is folklore; §5.1's kill-diag exists
because one of these hunts once ended in a tracer being written.

**Designed.** `brixtest lane status` — port 23112 has a foreign
occupant, owner record says pid 41213, session `9f31…`, started
11:02, still alive (F8). Or it doesn't, so: `brixtest fleet start-all
--json` — the `StartReport` says `ref-gsi` failed, phase `readiness`,
log tail inline (F3/F4); `brixtest prep --explain` says the snapshot
was rejected on ground 1, generator stamps mismatch (F7); `tail
events.jsonl | jq` shows the sentinel never tripped (F6/F15). Same
underlying facts in both columns — the difference is that the designed
system *answers questions*, where the grown one must be excavated.
Every command named here is an F14 verb whose payload is an F-spec
object; nothing in the story is aspirational beyond what §7.3 already
specifies.

### 7.9 The designed session, start to finish

The same composition as §7.7, laid out in time. Today this order
exists — but only as the emergent behavior of five exec'd conftest
shards whose ordering constraints live in comments (§2.5); the
designed plugin pins it with an ordering test (F10 parity) and this
table becomes its documentation:

| # | Step | Where | Features |
|---|---|---|---|
| 1 | Plugin activates `HarnessConfig`; `SuiteSettings.from_env()` frozen; markers registered | every process, `pytest_configure` | F10, C2 |
| 2 | Lane acquired: ownership record written, foreign-lane refusal checked | controller only | F8 |
| 3 | Artifact prep: restore-or-generate per step | gw0 only | F7 |
| 4 | Collection: declaration-gate analysis over the selected tests, cache-backed; `--collect-only` short-circuits every later step (the history-§11 optimization, preserved as contract) | all processes | F5 |
| 5 | Fleet freeze: registry sealed, `FleetPlan` computed from the declared closure | controller | F1, F5→F3 |
| 6 | Start: dependency-leveled parallel start through the backend; probes; stability window | controller | F3, F9, F4, F6 |
| 7 | Conservation baseline snapshot | controller | F6 |
| 8 | Tests run; sentinel piggybacks on per-test hooks; workers never touch lifecycle | all processes | F6, F10 |
| 9 | Stop sweep with quiescence proof; conservation final + delta; ownership-checked orphan reap | controller | F3, F6, F8 |
| 10 | Lane released: ownership record removed, event stream flushed | controller | F8, F15 |

Each row is an existing behavior with an existing owner; the table's
only addition is that the order is *stated*, so a regression in it is
a test failure instead of a haunting.

### 7.10 The additive-feature gate ledger

R13's discipline — parity commits never carry additions — needs an
audit surface. Every additive item from §7.3 ships behind exactly one
of three gate shapes: a settings field, a new CLI/API surface (inert
until called), or an internal change with a graduation criterion.
Reviewers check this ledger, not the diff, to decide whether a change
was parity or additive; a new additive feature is not merged until it
has a row here:

| Additive feature | F | Gate shape | Ships as | Graduates when |
|---|---|---|---|---|
| strict spec validation | F1 | settings field | warn-only | one full phase warn-clean in the migration lane → refuse |
| `to_dict`/`from_dict` | F1 | new API | on | — (semver'd from birth) |
| kind extension point + contract kit | F2 | new API / test kit | on | kit green for all six in-tree kinds |
| `FleetPlan` / `StartReport` | F3 | new API | on | F14 consumes them |
| `Probe` objects (`CommandProbe`) | F4 | per-spec opt-in; alias strings untouched | off | first in-tree spec converted + soaked |
| gate modes `enforce\|warn\|off` | F5 | settings field | `enforce` (today's) | — (default never changes) |
| `gate explain` | F5 | CLI verb | on | — |
| gate-cache schema stamp | F5 | internal | on | first schema bump invalidates cleanly |
| `owns()` public + conservation reports | F6 | new API / write-only artifact | on | history-§10 regression green post-move |
| `PrepStep` protocol | F7 | internal | on | all eight steps ported 1:1 |
| `prep --explain` | F7 | CLI verb | on | — |
| lane ownership record | F8 | written always; *consulted* behind a flag | write-on, consult-warn | one phase of warn logs clean → reaper refuses on it |
| `lane status` | F8 | CLI verb | on | — |
| `backend_contract` suite | F9 | test-only | on | `LocalBackend` green now; `K8sBackend` at TS-9 |
| `HarnessConfig` activation | F10 | parallel wiring path | legacy default | migration lane runs it for one full phase |
| worker frame error objects | F11 | protocol version field | v0 frames | worker + proxy both speak v1 |
| `StubServer` base | F12 | per-stub opt-in | base + `OriginStub` shipped, inert until a spec spawns one | each grown stub converts as its own commit |
| strict template scan | F13 | settings field | off | brace whitelist inventoried (TS-6) → warn → on |
| `--json` + exit-code contract | F14 | new flags | on | schema frozen at 1.0 |
| event stream | F15 | settings field | on (write-only) | schema v1 declared at TS-8 |
| artifact catalog | F16 | new API + `artifacts` CLI verb | on (publishing is opt-in per prep step) | all eight prep steps publish their outputs (TS-2) |
| service log views | F17 | new API + `logs` CLI verb | on | first ten migrated tests use `mark()`/`wait_for` (TS-4) |
| per-test workspaces | F18 | new fixture (`workspace`) | on, alongside `tmp_path` | basetemp uses inventoried → shimmed → gone (TS-4) |
| `wait_until` | F19 | new API | on | hand-rolled sleep-loops counted at TS-4, burned down by TS-6 |
| payload factory | F20 | new API | on | transfer tests verify by seed, not by pre-copied fixture files (TS-5) |
| per-test capture | F21 | settings field (`capture_results`) | on (write-only) | first triaged failure resolved from the record alone (TS-4) |
| run store + OpenSearch export | F22 | new API + `results`/`export` CLI verbs | on (write-only; export inert until called) | schema v1 frozen at 1.0; first external dashboard fed by export |
| results portal | F23 | new CLI verbs (`report`/`portal`) | inert until called | report attached to a real bug report instead of scrollback |
| dynamic per-test servers | F24 | new API (`fleet.request_server`) | inert until called | per-worker port striping lands for xdist block sharing |
| resource watch + benchmarks | F25 | settings field (`watch_resources`) | on (write-only findings) | one full phase with zero false findings → findings can gate CI |

The pattern to notice: **nothing in this table changes a default
behavior on the day it lands.** Additions are inert, opt-in, or
write-only until their graduation row says otherwise — that is what
keeps NG2 checkable while the framework still gets better.

### 7.11 The test-services layer (F16–F20)

The F1–F15 catalogue covers what the *harness* does. This section
covers what every *test* does — get an artifact, read a service log,
make scratch space, wait for something, move provable bytes — and the
grown suite's answer to each was "every test file for itself." These
five features share one design rule, the **uniform addressing rule**:

> A cross-cutting service is reachable by the same name from a test
> (through the `fleet` fixture), from the CLI, and from a REPL — and a
> miss anywhere produces the same C1 error naming what *does* exist.

That rule is what makes tests readable (the call names the intent),
debuggable (the operator can replay the exact lookup a failing test
made), and deployable (nothing in a test hard-codes where a lane —
local or, later, a k8s namespace — keeps its files).

#### F16 — the artifact catalog (`brixtest.services.artifacts`)

*Grown today:* prep builds CA material, JWT keys, and data trees;
consumers reach them by re-assembling paths from settings constants.
Every consumer hard-codes the tree's shape, and the fleet-key-desync
incident (memory: `fleet_key_desync_signature`) was precisely a
consumer's idea of "the key" drifting from the fleet's.

*Designed:* prep steps **publish** what they build —
`artifacts.publish("ca.cert", path, note="test CA")` — and everyone
else resolves the name: `fleet.artifacts.path("ca.cert")` in a test,
`brixtest artifacts path ca.cert` at the shell, `artifacts list` for
discovery. The catalog file lives *inside* the artifact tree, so the
F7 snapshot cache restores names and bytes as one unit: whichever
generation of the tree a lane holds, its names resolve to that
generation's files — never a mix. Publishing a path *outside* the
tree is a `SpecError` at publish time, because such a file would
silently vanish from the name→bytes bond on the next restore.

*Failure modes:* unknown name → `ArtifactNotFound` listing every
published name and the catalog path; cataloged-but-missing file →
the same error with "re-run: brixtest prep" appended; both carry
`— try: brixtest artifacts list`.

#### F17 — service log views (`brixtest.services.logs`)

*Grown today:* tests build `/tmp/xrd-test/logs/<server>.log` paths by
hand and grep the whole file — matching lines caused by tests that ran
minutes earlier, which is how "flaky assertion on a log line" bugs are
born.

*Designed:* `view = fleet.log_view("webdav")` gives a `LogView` with
the two honest operations made first-class: `mark()` captures the
current end of the log **before** the test acts, and every read —
`lines(since=mark)`, `grep(pattern, since=mark)`,
`wait_for(pattern, since=mark, timeout=…)` — scopes to *what this
test caused*. A `str` pattern is a substring; regex requires a
compiled pattern (no accidental-metacharacter class of bug). Views
are rotation-aware: a file that shrank below the mark is read from
the top rather than silently yielding nothing. The CLI speaks the
same address: `brixtest logs webdav --tail 40`, `--path` for the
location itself.

*Failure modes:* `wait_for` timeout → `LogWaitTimeout` carrying the
instance, the pattern, the wait, and the current tail — the assertion
message *is* the debugging session, and it ends with
`— try: brixtest logs <name> --tail 40`.

#### F18 — per-test workspaces (`brixtest.services.workspace`)

*Grown today:* a mix of pytest `tmp_path` (whose shared-basetemp
rotation raced under xdist — memory:
`pytest_shared_basetemp_rotation_race` — one worker's numbered-dir
cleanup deleting another's live scratch tree) and bare
`tempfile.mkdtemp()` into system `/tmp`, where lane isolation and tmp
reapers don't apply.

*Designed:* the `workspace` fixture returns a fresh directory under
`<lane>/workspaces/`, **named for the test's nodeid** so a human finds
it from a failure message, with uniqueness by counter (`…-2`, `…-3`)
— an old workspace is never emptied and reused. Everything lives
inside the lane (F8's isolation covers scratch space for free), and
`sweep()` deletes only directories *this allocator created in this
process* — the substring-reaper incident's lesson applied to files.
Retention is explicit, never ambient.

*Failure modes:* none silent — collision-by-design is impossible
(`mkdir(exist_ok=False)` + counter), and a foreign directory under
`workspaces/` is simply never touched.

#### F19 — uniform waiting (`brixtest.services.waiting`)

*Grown today:* dozens of hand-rolled `while … sleep` loops, some
gating on the wall clock — and on hosts where the wall clock steps
backwards (the WSL2 incident class, memory:
`wsl2_clock_backwards_steps`) a wall-clock deadline can be negative
seconds away.

*Designed:* one spelling —
`wait_until(predicate, timeout=…, what="the redirect to land")` —
with three rules enforced once so no test re-decides them:
`time.monotonic()` only; every wait *names* what it is for; the
predicate's last falsy observation rides along into the error. A
predicate that raises is a caller bug and propagates immediately —
swallowed exceptions inside wait loops are how the grown suite's
worst hangs hid their cause.

*Failure modes:* `WaitTimeout("gave up waiting for the redirect to
land after 10.0s (last observed: '')")` — a sentence, not a stack
trace into an anonymous lambda.

#### F20 — deterministic payloads (`brixtest.services.payloads`)

*Grown today:* transfer tests mixed `os.urandom` (unreproducible — a
corrupt byte can't be diffed against what should have been there),
`dd` subprocesses, and hand-rolled checksum loops.

*Designed:* a payload is a pure function of `(seed, size)` — a
SHAKE-256 counter stream, C-speed, incompressible, chunked so
multi-GB files never sit in memory. `make_payload(workspace,
size=8<<20, seed=42)` → upload → download →
`verify_payload(dest, payload)`. Same seed, same bytes, any host, any
run: a failure five runs later reproduces the exact bytes that
failed.

*Failure modes:* verification raises `SpecError` naming the **offset
of the first differing byte** — the number a transfer bug report
actually needs — or the size mismatch, before any byte comparison.

### 7.12 The run-intelligence layer (F21–F25)

The services layer (§7.11) gave each *test* uniform access to the
fleet. This layer gives each *run* a memory: every test's full output
captured on disk, every run catalogued in a queryable store, a portal
that advertises the results, servers spawnable per-test from a
dedicated port block, and a resource watch that samples every server
pid for the whole session so a crash, a leak, or a CPU spike is a
**named finding** instead of a mystery in a later test's stack trace.
The five features share one spine — the run store — and one honesty
rule: under `pytest-xdist`, capture and storage happen only on the
controller (the `logstart`/`logreport`/`logfinish` hook trio is
forwarded there by xdist itself), while dynamic-server release runs in
every process that requested one. Implemented same-day as a third
wave: `brixtest/results/` (model, store, collector, report),
`brixtest/fleet/dynamic.py`, `brixtest/harness/resources.py`, plus the
`results`/`report`/`export`/`portal` CLI verbs.

#### F21 — per-test capture (`brixtest.results.collector`)

*Grown today:* a test's evidence evaporates at the prompt. stdout is
whatever `-s` happened to show, the failure text is truncated by
terminal width, and "which server lines belong to this test" means
grepping a shared multi-megabyte log by timestamp — on a host whose
clock steps backwards ([[wsl2_clock_backwards_steps]]), a losing game.

*Designed:* every test invocation produces a `TestRecord` and an
output directory `<lane>/results/<run_id>/tests/<stem>-<sha1[:8]>/`
containing `record.json` (outcome, per-phase wall times, servers,
markers, params, workspace, artifacts touched), `stdout.txt` /
`stderr.txt` with per-phase sections, and `logs/<name>.log` — a slice
of each relevant server's log covering exactly this test's lifetime.
Relevance is the F17 mark discipline applied automatically: at
`logstart` the collector marks a `LogView` for every server the test's
*file* declares (the F5 gate already knows), and any dynamically
requested server joins the set from birth (its whole log *is* the
test's). The failing `longrepr` is stored in full — never truncated —
and capture is a write-only addition: no pytest default changes, no
test sees a new fixture unless it asks.

*Per-test cost (as built):* the record also carries the test's own
resource bill — `cpu_seconds` (rusage self+children delta across the
test, so a subprocess-heavy test is charged for its children),
`rss_delta_kb` (test-process VmRSS delta) and `maxrss_kb` (`ru_maxrss`
high-water at test end). The probe (`brixtest.util.testprobe`) runs in
whatever process executes the test — the serial session or an xdist
worker — and its verdict rides the **teardown report's
`user_properties`** as flat `(str, float)` pairs, because that is the
one channel xdist serializes to the controller intact; the collector
folds them into the record there. The same channel carries
`brixtest_dynamic` (comma-joined names of servers the test requested
on a worker), which is how dynamic membership survives xdist at all.

*Failure modes:* the collector is built on the `logstart`/
`logreport`/`logfinish` trio precisely because a `hookwrapper`
around `makereport` does **not** get forwarded by xdist — the
tempting implementation silently records nothing under `-n auto`.
Records for tests that die in setup still exist (outcome folds from
whichever phases ran); a nodeid mismatch between hooks is a guarded
no-op, not a corrupted record. Open records are **keyed by nodeid**,
never held as "the current test": under xdist the workers' hook
streams arrive interleaved, so one record per worker is legitimately
open at any moment — a single-current-record collector silently drops
whichever test another worker started over (found by counting store
rows against the run: 11 of 13). The nodeid-less `note_*` calls
(workspace, artifacts) still target the latest-started record — exact
serially, best-effort under xdist. Dynamic-server **log slices** are
not captured under xdist (the logs live where the worker ran; only
the names travel) — a documented degradation alongside the empty
markers/params columns.

#### F22 — the run store (`brixtest.results.store`)

*Grown today:* run history is scrollback. Comparing tonight's wall
times against last week's, or asking "when did this server's RSS
start growing", requires having saved the terminal output — nobody
did.

*Designed:* a stdlib-`sqlite3` store at `<lane>/results/brixtest.db`
— one file, no daemon, no dependency — with four tables: `runs`
(counts, wall, port base, host), `tests` (one row per invocation,
JSON columns for servers/markers/params/artifacts), `samples` (the
F25 timeline), `findings` (the F25 verdicts). A `schema_info` version
stamp is checked on open; a *future* schema is refused with a named
error rather than half-read, while an **older** schema is migrated in
place — schema v2 added the per-test cost columns (`cpu_seconds`,
`rss_delta_kb`, `maxrss_kb`, appended *last* so a fresh create and an
ALTER-migrated v1 agree on column order), and the migration checks
`PRAGMA table_info` per column so a half-applied upgrade converges
instead of failing on "duplicate column". OpenSearch is an **export target, not a
dependency**: `export_opensearch()` emits bulk-API JSONL (action line
+ document line) across `brixtest-tests|findings|instances` indices,
so feeding a cluster is `curl --data-binary @run.jsonl .../_bulk` —
the suite itself never needs the network.

*Failure modes:* one connection guarded by a lock
(`check_same_thread=False`) because the sampling thread and the hook
path both write; read-only CLI verbs on a lane with no store answer
with a hint (`run the suite first`) and **never** create an empty
database — a read must not fabricate state.

#### F23 — the results portal (`brixtest.results.report`)

*Grown today:* "what failed last night" is answered by re-running or
by asking whoever saw it. There is nothing to link in a bug report.

*Designed:* `write_report()` renders one **self-contained** HTML file
per run — inline CSS/JS, zero external assets, so it survives being
mailed, attached to an issue, or opened off a USB stick years later.
Summary tiles, findings cards, a filterable/sortable test table whose
rows expand into the full record (failure text included, plus the
F21 cost columns — `cpu s` sortable in the table, ΔRSS/maxRSS in the
expanded record), a **test↔server map** (an HTML matrix off the
store's observed rows: which files touched which servers, dynamic
requests counted — `results/mapping.py`, shared with the CLI `map`
verb), and the per-instance resource benchmark with **inline-SVG
timelines** (`results/charts.py`: one RSS and one CPU sparkline per
instance off the store's sample series, stride-downsampled to a fixed
point budget with the last point preserved, CPU pinned to a zero
floor so flat-but-busy reads level — no scripts, no assets, the
one-file promise intact). `write_index()` lists runs;
`brixtest portal` serves the results tree with the stdlib
`ThreadingHTTPServer` — files only, no handlers, no API — on the
lane's **top port** by convention, so it lives inside the addressed
range ([[host_literal_migration_complete]]) and the F24 allocator's
listening-port skip makes coexistence safe.

*Failure modes:* an unknown run id fails with the C1 shape —
`RunStoreError: … — try: brixtest results list`. The portal serves
static files exclusively; there is deliberately no write path from
the browser.

#### F24 — dynamic per-test servers (`brixtest.fleet.dynamic`)

*Grown today:* a test needing its own server instance either mutated
shared fleet state (the frozen-registry invariant exists because that
went wrong — [[fleet_key_desync_signature]]) or hand-rolled a
subprocess with a hand-picked port that collided the day two lanes
ran at once ([[bucket3_port_contention_classified]]).

*Designed:* `fleet.request_server(kind=...)` — the same `KindProfile`
machinery as the static fleet, but through a **separate, never-frozen
`Registry`** and its own `LocalBackend` on the same lane, so the
launcher's frozen invariant is never weakened. Ports come from a
dedicated block `[port_base+offset, port_base+offset+…)` (default
offset 700) with a cursor allocator that skips allocated ports,
*listening* ports, and — because lane ranges sit inside the host's
`ip_local_port_range`, where any outbound connection's *source* port
can land — every port a `SO_REUSEADDR` bind-probe cannot take right
now (the probe sees exactly what the launched child's own bind will
see: pure TIME_WAIT passes, live sockets fail), wrapping exactly once
before raising `PortExhaustedError`. If the child's bind still loses
the race, `request()` proves the theft (the port is no longer
bindable), emits `dynamic.port_stolen`, and renumbers-and-relaunches
up to three times; a `StartError` on a still-bindable port is the
command's own fault and is raised as-is. Names are `dyn-<test-stem>-<n>` from a
counter that never resets — a name is never reused within a run, so
log slices and store rows can never alias
([[pytest_shared_basetemp_rotation_race]] generalized). Scope is
`test` (released at `logfinish`) or `session`; release is a
quiescence proof — survivors are *named* in a `QuiescenceError`, and
a failed launch releases its ports on the way out.

*Failure modes:* the documented xdist gap — workers share the one
dynamic block with no per-worker striping. The bind-probe plus the
stolen-port retry make cross-process collisions *handled* rather than
merely unlikely (each worker's allocator probes the same kernel
truth), but allocation order across workers stays nondeterministic;
per-worker striping — deterministic block sharing — remains this
feature's graduation criterion, not a silent assumption. Host
hygiene: lane blocks live inside `ip_local_port_range`, so reserving
them (`sysctl net.ipv4.ip_local_reserved_ports`) removes the theft
class at the source on hosts you control.

#### F25 — the resource watch (`brixtest.harness.resources`)

*Grown today:* the sentinel (F6) notices a server *dying*; nothing
notices one *suffering*. A leaking daemon is discovered when the host
swaps; a CPU-pinned server surfaces as timeout noise attributed to
whichever innocent test ran next ([[host_load_excuse_debunked]] — the
excuse survives exactly as long as nobody is measuring).

*Designed:* a sampling thread (default 1 s) walks every pid a
composed provider reports — static fleet (pidfile first; else the
port), backend-spawned children, dynamic servers — reading
`/proc/<pid>/stat` (utime+stime → CPU%, parsed after
`rpartition(")")` so a comm with spaces cannot shift the fields) and
`/proc/<pid>/status` (VmRSS). Every sample is attributed to the test
running at that instant and batched into the store: the benchmark the
request asked for, for every test and the whole suite. Three
detectors, each a `Finding` in the store, the terminal summary, and
the portal: **crash** (pid vanished from `/proc` *and* the provider,
re-asked, still claims it — the re-confirm closes the race where a
deliberate release looks identical), **cpu-spike** (CPU ≥ threshold
for N consecutive samples, reported exactly once per instance/test),
**leak** (decided at stop over the whole series: least-squares RSS
slope ≥ threshold **and** total growth ≥ a floor — both bounds must
trip, so a short noisy series or a one-off allocation cannot fake
one). All timing is monotonic, re-anchored to the epoch once
([[wsl2_clock_backwards_steps]]).

*Failure modes:* ordering is load-bearing — `sessionfinish` stops the
sampler **before** any teardown, or every released server reads as a
crash. Thresholds live in a frozen `ResourcePolicy` on
`HarnessConfig`; the defaults are deliberately conservative
(512 kB/min slope *and* 8 MB growth) because a false leak verdict
teaches people to ignore findings. Under xdist, a sample's
`during_test` attribution is ill-defined by construction — several
tests run at once, and the sampler (on the controller) tags the last
`logstart` it saw; the per-instance series and the detectors are
exact regardless, only the "which test was running" column degrades.
Per-test *cost* is unaffected — that is F21's probe, measured in the
worker itself.

*The claim rule (as built, found by drill):* crash detection only
works if the provider keeps claiming a dead pid, so
`LocalBackend.process_pids` reports every spawned child it has not
been asked to stop — dead or alive (its `poll()` also reaps, which is
what makes the /proc vanish observable). Children of daemonizing
kinds (profile carries a pidfile) exit by design and are dropped; the
pidfile pid is the claim there, and a stale pidfile *is* the crash.
The dual: a deliberate `stop()` withdraws the claim **before** the
first signal, or a sweep racing the kill window reads the release as
a crash. All three detectors are proven live by drills: a SIGKILLed
dynamic server → crash finding with test attribution; a busy-loop
kind → cpu-spike after the streak; an allocating kind held to session
scope → leak verdict at `resources.stop()`.

### 7.13 The eight operator asks — requirements traceability

The 2026-08-17 operator request, restated as eight numbered
requirements and traced to the features (and modules) that answer
them. Four were already delivered by F1–F25; four landed in the
seventh pass:

| # | Ask | Answer | Where |
|---|---|---|---|
| i | only launch servers registered with the tests being run | F5 declaration gate: the booted set is `specs_to_boot(closure of declared files)`; undeclared use refuses in the C1 shape | `harness/gate.py`, `fleet/declares.py` |
| ii | graphical map and/or table of the test↔server mapping | one `Rows` shape, two sources — *declared* (gate closure over files, no runtime needed) and *observed* (store rows, dynamic counts) — three renders: ASCII matrix, Mermaid graph, HTML matrix in the report; CLI `map [--run] [--mermaid]` | `results/mapping.py`, F14, F23 |
| iii | detect servers that crash during the run | F6 sentinel (mid-run abort, culprit test named, `fleet-died.json`) + F25 crash detector (finding with per-test attribution) + conservation delta | `harness/sentinel.py`, `harness/resources.py` |
| iv | track/profile server mem/cpu over the suite | F25 sampling thread → `samples` table → per-instance stats + inline-SVG RSS/CPU timelines in the report | `harness/resources.py`, `results/charts.py` |
| v | track/profile mem/cpu/lifetime of individual tests | F21 probe: rusage self+children CPU delta, VmRSS delta, `ru_maxrss`, plus wall per phase — measured in the executing process, shipped over teardown `user_properties` (xdist-safe), stored as schema-v2 columns, surfaced in report + `results show` | `util/testprobe.py`, `results/{model,store,collector}.py` |
| vi | run tests multi-threaded | pytest-xdist support: controller-side boot from `pytest_xdist_node_collection_finished`, worker-safe fixtures, probe/dynamic forwarding; green `-n 2` on 3.13 and 3.9 | `harness/plugin.py` |
| vii | tests within a file are a linear stream with correct artifact state | `HarnessConfig.file_linear` (default on) upgrades xdist's implicit `--dist load` to `loadfile` scheduling — a file's tests stream in order on one worker; explicit operator dist choice wins; only in-file order is promised | `harness/plugin.py` (F10) |
| viii | tests/servers isolated from each other — locally and later k8s | local: F8 lanes + port ledger + ownership-checked reaping, a lane-claim gate that refuses a reap another live harness owns, F24 dedicated dynamic block with bind-probe + stolen-port retry; k8s: the F9 `DeployBackend` seam is the designed landing zone (TS-9, future — §8.3) | `config/lanes.py`, `fleet/dynamic.py`, `orphans.py`, `deploy/` |

viii-k8s is the one deliberately open half: everything else in the
row set is implemented and behaviorally verified (serial, `-n 2`,
py3.13 + py3.9, drills).

The lane-claim gate is the newest part of that row and it was added the
expensive way.  Ownership inside a lane was already exact — `orphans.owns`
matches whole path components, so `/tmp/xrd-test` never reaches into
`/tmp/xrd-test-a15aa`, and the parent-argv rule catches the nginx worker whose
own command line names nothing.  What none of it answered is the question one
level up: *is this root mine?*  A lane root is derived from the test file name
(`test_audit16aa…` → `/tmp/xrd-16aa`), so a root read off a `ps` listing
carries no session identity at all, and a fleet mid-run is indistinguishable
from an abandoned one.  On 2026-08-19 a root read that way was reaped and took
roughly 200 processes of a concurrent run with it.  Precision on the wrong
boundary is not safety.

The fix reads the declaration rather than the listing.  A harness puts
`TEST_ROOT` in its own environment; `/proc/<pid>/environ` says so for every
live process, and that is a claim nothing else forges.  `lane_claimants()`
returns everyone declaring a root, `live_lanes()` maps the whole host, and
`kill_orphans(..., force=False)` — the default — raises `ForeignLaneError`
naming the pids rather than killing them.  A harness reaping its own lane is
exempt automatically, because the claimant is the caller or one of its
ancestors, so conftest teardown needed no change to keep working.

Two narrowings keep the gate from becoming noise, and each is pinned by a
test.  `TEST_ROOT` is inherited by everything a harness shell launches, so the
default lane on this host showed 22 live "claimants" that were a CodeChecker
analyze fleet working under `<root>/tmp/` — live in the lane, unharmed by its
teardown, and enough to block every routine reap.  Only *harnesses* gate a
reap.  And harness-ness is decided per argv token's basename, never by
substring: every path under pytest's own `tmp_path` begins
`/tmp/pytest-of-<user>/`, so a raw `"pytest" in cmd` reads the directory a
process works in as the program it runs — which is how the first cut of this
gate failed its own test, and would on a real host have let any linter handed
a temp path hold a lane hostage.  A gate that fires on the routine case gets
`force=True` pasted over it, and then it protects nothing.  Gate:
`tests/test_ci_lane_ownership_gate.py`.

---

## 8. Deployment Model: Local Now, Kubernetes Later

### 8.1 The backend seam

All process mechanics move behind one interface (extracted in TS-4 from
the launcher's existing method surface — this is a *refactor* of code
that already exists, not new capability):

```python
class DeployBackend(Protocol):
    """Where and how instances run. Everything above this line is
    backend-agnostic: specs, kinds, dependency order, readiness
    *policy*, lanes, the declaration gate, the pytest plugin."""
    def prepare(self, lane: Lane, artifacts: ArtifactSet) -> None: ...
    def start(self, spec: InstanceSpec) -> ServerEndpoint: ...
    def stop(self, name: str) -> None: ...
    def endpoint(self, name: str) -> ServerEndpoint: ...
    def is_ready(self, spec: InstanceSpec) -> bool: ...
    def logs(self, name: str) -> Path: ...
    def process_snapshot(self) -> Mapping[str, object]: ...  # conservation input
```

### 8.2 `LocalBackend` — the only implementation this plan delivers

Behavior-identical packaging of today's launcher mechanics:

- fork/exec with per-kind starters; pidfile locations per `KindProfile`;
- **unprivileged by construction**: every fixed port ≥ 1024 (measured
  floor today: 8080; Appendix D), per-lane dynamic ranges from
  `port_ladder`, no capability or root requirement anywhere in the
  start path (the sole privileged flow, `run_multiuser_authz.sh`, is an
  explicitly separate sudo-wrapped lane and stays outside the backend);
- lane-scoped prefixes, logs, and data roots under `TEST_ROOT`;
- readiness via TCP/protocol probes; stop via kind profile; quiescence
  via one-sweep listener survey; conservation via process snapshot.

### 8.3 `K8sBackend` — future work the seam must not preclude

Not built in this plan (TS-9, unscheduled). The design target, so the
seam is cut in the right place: the same `InstanceSpec` maps onto
containers —

| Local concept | k8s mapping |
|---|---|
| spec + kind starter | Deployment (or Pod) per instance, image per kind |
| rendered config file | ConfigMap mounted at the template's target path |
| artifact set (PKI/tokens/keytabs) | Secrets mounted per instance |
| `readiness=` probe | container readinessProbe (TCP/exec) |
| `ServerEndpoint(host, port)` | Service DNS name + port (client access via in-cluster test pod, NodePort, or port-forward — TS-9 decision) |
| lane | namespace (one lane = one namespace; deletion = teardown) |
| orphan reaping / conservation | namespace-scoped resource accounting |
| `requires=` dependency levels | startup ordering / init gates |
| clients & tests | a test-runner pod running this same suite with `K8sBackend` selected |

Prior art to build on, already in-repo: the `k8s-tests/` interop lab
(Helm charts under `k8s-tests/charts/gridftp-interop/` with the
`brix-common` and `topology-role` subcharts), `k8s-tests/pki-scripts/`
(e.g. `generate-jwt-keys.py` — an early, chart-side duplicate of the
artifact factory that a `K8sBackend` would retire), and the
`k8s-tests/remote-suite` in-cluster suite (whose module-basename clash
with `tests/` was §2.2's first incident — packaging is what makes
sharing code with it possible at all).

### 8.4 Core rules that keep the k8s door open (enforced from TS-4)

1. Nothing above the backend touches `os.fork/exec`, pidfiles, `ss`, or
   `/proc` — those are `LocalBackend` internals (mirrors the C side's
   VFS-seam discipline, INVARIANT 12).
2. No `127.0.0.1` literals above the backend; hosts come from specs and
   endpoints (the host-literal migration of 2026-07 already cleared the
   test side; the guard reruns each sweep).
3. Readiness is expressed as probe *descriptions* on the spec (already
   true: the spec's `readiness` alias strings, F4), executed by the
   backend.
4. Logs are reached through `backend.logs(name)`, never by joining
   `TEST_ROOT` paths in test-facing code.
5. Artifacts are described as an `ArtifactSet` manifest (name → path +
   role) so a backend can re-materialize them as Secrets.
6. Template rendering resolves paths through backend-supplied values
   (already the mechanism: `template_values` + `_endpoint_template_values`),
   never hard-coded absolute paths in templates that would differ
   in-container.

---

## 9. Target Architecture

### 9.1 Directory layout (full)

```
BriXTest/
├── pyproject.toml              # PEP 621 metadata, deps, extras, scripts, tool config
├── README.md                   # BriXTest front door
└── src/
    ├── brixtest/               # GENERIC CORE — no nginx/XRootD/WLCG knowledge
    │   ├── __init__.py         # __version__ only — imports NOTHING, reads NO env
    │   ├── config/
    │   │   ├── settings.py     # SettingsBase machinery + install_legacy_module
    │   │   ├── lanes.py        # Lane model: root + port-base + ownership refusal
    │   │   └── ports.py        # PortLedger: ladder math, declared-port accounting
    │   ├── fleet/
    │   │   ├── registry.py     # spec registry (today's server_registry, generic names)
    │   │   ├── specs.py        # InstanceSpec/CommandSpec/ServerEndpoint + KindProfile
    │   │   ├── launcher.py     # dependency-leveled start/stop engine + facade
    │   │   ├── harness.py      # LifecycleHarness (per-test facade)
    │   │   ├── prep.py         # artifact pipeline + snapshot-cache engine
    │   │   ├── declares.py     # AST declaration gate (fleet_declares)
    │   │   ├── orphans.py      # owns()/kill_orphans (fleet_orphans)
    │   │   └── errors.py       # launcher exception types
    │   ├── deploy/
    │   │   ├── backend.py      # DeployBackend protocol + ArtifactSet (§8.1)
    │   │   ├── local.py        # LocalBackend: fork/exec, pidfiles, unprivileged ports
    │   │   └── k8s.py          # TS-9 placeholder — interface notes only
    │   ├── harness/
    │   │   ├── plugin.py       # pytest11 plugin: every hook from §5.1
    │   │   ├── session.py      # SessionLifecycle (ex _setup_session et al.)
    │   │   ├── gate.py         # declaration gate + persistent cache
    │   │   ├── sentinel.py     # watchdog + conservation (ex part4)
    │   │   └── fixtures.py     # registry/lifecycle/test_env/... fixture defs
    │   ├── clients/
    │   │   ├── procworker.py   # out-of-process client-worker protocol (ex _xrdcl_*)
    │   │   └── pty.py          # cli_pty
    │   ├── util/
    │   │   ├── proc.py         # process/port half of lib_py/util + ephemeral_port
    │   │   ├── net.py          # wait_tcp / readiness executors
    │   │   └── configtext.py   # config_parse, config_templates, render_cfg
    │   └── cli/
    │       └── main.py         # `brixtest fleet|prep|run` subcommands
    └── brix_suite/             # NGINX-XROOTD ADAPTER — this suite's knowledge
        ├── settings.py         # SuiteSettings: the 258 fields + Tier-2 knobs (§5.8)
        ├── catalogue.py        # the 126 specs (fleet_specs + part2 + fleet_values)
        ├── ports.py            # the fleet_ports* tables + fixed-port families
        ├── kinds.py            # KindProfile rows + nginx/xrootd/xrdhttp/haproxy
        │                       # starters & renderers; registers into brixtest
        ├── nginx_tools.py      # THE single copy of _nginx_bin/_inject_* helpers
        ├── security/
        │   ├── pki.py          # pki_helpers (lib_py/pki -> _legacy; see TS-5)
        │   ├── proxy.py        # wraps repo utils/make_proxy.py
        │   ├── tokens.py       # TokenForge + TokenIssuer + Manifest (mixins dissolved)
        │   ├── tokens_vectors.py   # token_differential (Layer-3 driver)
        │   ├── x509.py         # x509forge Cert et al. (parts dissolved)
        │   ├── x509_vectors.py         # x509_differential
        │   ├── x509_matrix_vectors.py  # x509_matrix_differential (stays separate)
        │   └── kdc.py
        ├── clients/            # xrdcl worker config, http.py, gridftp.py
        ├── servers/            # the 8 stub servers (tests/lib/*.py)
        ├── mesh/               # cms.py, hybrid.py, wlcg.py, config.py
        ├── perf/               # load_test (+parts), _perf_ab, _perf_netem
        ├── interop/            # official_interop_lib, backend_matrix, gridmap helpers
        ├── cachemx/            # _cachemx* modules
        ├── util/               # metrics.py, matrix.py, frm/tpc parse helpers
        ├── guards/             # source_guards_lib + suite-side guard helpers
        ├── harness_ext.py      # suite fixtures (ref_xrootd, mu.py content) + wiring
        ├── prep_steps.py       # the concrete fleet_prep pipeline steps
        ├── _legacy/            # lib_py/dedicated.py + tombstones; deprecation-warned
        └── data/               # asset() locator (TS-6); physical assets stay in tests/
```

Activation wiring: `tests/conftest.py` (which keeps its name) eventually
reduces to `pytest_plugins = ["brixtest.harness.plugin"]` plus one call
that hands the plugin its adapter configuration — settings instance,
catalogue registrar, kind registrations, prep steps — and the legacy
re-exports (§10).

### 9.2 Class design specs

#### 9.2.1 `SuiteSettings` (adapter) on `brixtest.config` machinery

The 258 module globals become one frozen dataclass with the same names as
fields, grouped by concern, plus derived-path properties:

```python
@dataclasses.dataclass(frozen=True)
class SuiteSettings:
    # lane identity
    test_root: str                  # TEST_ROOT
    port_start: int                 # TEST_PORT_START
    host: str                       # TEST_HOST, default 127.0.0.1
    host6: str                      # TEST_HOST6, default ::1
    # registry behavior
    registry_enabled: bool          # TEST_SERVER_REGISTRY != "0"
    registry_start: bool
    registry_keep_logs: bool
    registry_strict_templates: bool
    # binaries
    nginx_bin: str                  # TEST_NGINX_BIN
    asan_nginx_bin: str
    brix_bin: str; xrdfs_bin: str; xrdcp_bin: str
    # remote mode
    remote_server: bool
    # the port ledger (all 178 fixed ports live here, not as loose fields)
    ports: PortLedger

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "SuiteSettings": ...
    def derive(self, **overrides) -> "SuiteSettings": ...
    # derived paths as properties: pki_dir, data_root, tokens_dir, tmp_dir,
    # artifacts_dir, registry_root, fleet_ready_marker, log_dir, cwd_dir
```

The Tier-2 runtime knobs of §5.8 (sentinel family, prep-cache switch,
sanitizer/valgrind wraps, run-as user, …) each become a field here too —
§5.8's table is the TS-3 completeness checklist. The dataclass machinery,
`install_legacy_module`, and `Lane` live in `brixtest.config`; the fields
and defaults are adapter.

Design rules: `from_env` is the ONLY environment read in the package;
validation (`port_start` range sanity, root-collision refusal — today's
"owned by another or incomplete test fleet" message moves to
`brixtest.config.lanes.refuse_foreign_lane()`) is **warn-only for one
full phase** before it may refuse. The default instance is constructed by
the harness plugin at `pytest_configure` and injected via a session
fixture; the legacy `settings` module keeps its 258 names as module
attributes generated from the one instance (§10.2), so all 690 dependents
observe identical values.

`PortLedger` constraints, measured: settings carries 178 `*_PORT`
constants (families and values in Appendix D), each overridable via a
`TEST_*` env var of the same name, 414 test files import them by name,
and `check_ports_doc.py` requires every constant to appear **by name** in
`docs/10-reference/test-fleet-ports.md`. Therefore the ledger keeps one
named attribute per constant (dataclass fields or an enumerable mapping
with `__getattr__` — NOT computed-on-demand anonymous values), preserves
the `TEST_<NAME>` env-override convention mechanically, and exposes an
`iter_named_ports()` the updated guard consumes. `port_ladder` math stays
below it (§5.7 layering).

#### 9.2.2 `KindProfile` (core mechanism, adapter rows)

The kind ladders of §5.2 become one table consulted everywhere:

```python
@dataclasses.dataclass(frozen=True)
class KindProfile:
    kind: str                        # nginx | xrootd | xrdhttp | haproxy | proc | external
    pidfile: str | None              # relative to endpoint.prefix; None = untracked
    stop: str                        # "nginx-quit" | "signal-pidfile" | "port-kill" | "never"
    quiescent_by_ports_only: bool    # proc: True; external: never quiescent
    starter: Callable[..., None]     # adapter-supplied
    renderer: Callable[..., Path] | None   # adapter-supplied (render_nginx etc.)

# brix_suite/kinds.py registers the rows:
KIND_PROFILES = {
    "nginx":   KindProfile("nginx",   "logs/nginx.pid",  "nginx-quit",     False, start_nginx,   render_nginx),
    "xrootd":  KindProfile("xrootd",  "run/xrootd.pid",  "signal-pidfile", False, start_xrootd,  None),
    "xrdhttp": KindProfile("xrdhttp", "run/xrootd.pid",  "signal-pidfile", False, start_xrdhttp, None),
    "haproxy": KindProfile("haproxy", "logs/haproxy.pid","signal-pidfile", False, start_haproxy, None),
    "proc":    KindProfile("proc",    None,              "port-kill",      True,  start_proc,    None),
    "external":KindProfile("external",None,              "never",          False, start_external,None),
}
```

Every `if spec.kind ==` ladder in start dispatch, `stop`, `_quiescent`,
`_stop_from_disk` reads this table. Adding a kind becomes one row plus one
starter callable — for any BriXTest consumer, not just this suite. The
existing contract tests (stop-failure visits every spec; quiescence
skip/keep triad; pidfile-no-listener stop) pin the translation.

#### 9.2.3 Launcher recomposition (core engine)

- `brix_suite/nginx_tools.py` holds the **single** copy of `_nginx_bin`,
  `_inject_nginx_load_modules`, `_inject_nginx_runtime_paths` (today
  triplicated, §2.3).
- The mixin bodies move **byte-identical** (only imports change) into
  ordinary modules; the start engine, stop/quiescence, and waiting
  machinery are promotion candidates into `brixtest.fleet.launcher` /
  `brixtest.deploy.local` per the §7.2 rule; nginx rendering and
  xrootd-run-as logic stay adapter.
- Same MRO order as today's A, B, C for the assembled class; the
  `LifecycleHarness` facade moves as-is; exception types move as-is.

#### 9.2.4 `FleetPrep` (core engine, adapter steps)

`prepare()` and the snapshot cache (history §11) become a class so the
cache knobs stop being module constants, with the pipeline steps
(PKI → JWKS → signing key → fleet artifacts → issued JWTs → CRLs →
authdb → stage hook) supplied by `brix_suite.prep_steps`:

```python
class FleetPrep:
    def __init__(self, settings: SuiteSettings, *,
                 steps: Sequence[PrepStep],
                 cache_root: Path | None = None,       # default ~/.cache/nginx-xrootd/fleet-prep
                 cache_ttl: int = 4 * 3600,
                 generator_sources: tuple[Path, ...] = ()): ...
    def prepare(self) -> None: ...          # restore-or-generate
    def restore(self) -> bool: ...
    def snapshot(self) -> None: ...
```

The §11 unit tests (`test_fleet_prep_cache.py`) convert from
monkeypatch-heavy to constructor-parameter tests. Module-level
`prepare()` remains as a thin default-instance wrapper for the shim.

#### 9.2.5 `HarnessPlugin` (core) — the load-bearing change

Hook-by-hook mapping (source of truth: §5.1):

| Hook | Today | Target |
|---|---|---|
| `pytest_configure` | part3 (TMPDIR pin, markers, `_pytest_config`) | `plugin.py` → `session.SessionState.configure()` |
| `pytest_sessionstart` | part2 | `plugin.py` → `session.SessionLifecycle.start()` (worker + collectonly gates preserved as the FIRST lines) |
| `pytest_collection_modifyitems` | part3 (declaration gate + cache flush) | `plugin.py` → `gate.enforce()` |
| `pytest_collection_finish` | part5 (declared-subset fleet boot) | `plugin.py` → `session.SessionLifecycle.boot_declared()` |
| `pytest_runtest_setup` / `_teardown` | part5 | `plugin.py` (verbatim) |
| `pytest_sessionfinish` | part5 (conservation → stop sweep → orphan alarm → tree destruction) | `plugin.py` → `session.SessionLifecycle.finish()` |
| `pytest_terminal_summary` | part5 + conftest_mu | `plugin.py` / `brix_suite.harness_ext` |
| `pytest_generate_tests` | part5 (matrix) | `plugin.py` (verbatim) |
| fixtures (15 listed §5.1) | part5 + conftest.py + conftest_mu | core `fixtures.py` / adapter `harness_ext.py`, re-exported by the shim conftest |

Activation: `tests/conftest.py` keeps its filename and becomes
(eventually) `pytest_plugins = ["brixtest.harness.plugin"]` plus
re-exports of every name any test imports from `conftest` today (the TS-0
inventory enumerates these — measured zero outside the by-path loader,
§2.5). The plugin is ALSO registered under the `pytest11` entry point in
`pyproject.toml`, but **disabled by default** (`addopts`-gated) until
TS-2's soak completes, so installing the package cannot double-register
hooks against the shim conftest.

#### 9.2.6 CLI entry points

```toml
[project.scripts]
brixtest = "brixtest.cli.main:main"    # subcommands: fleet (start-all|stop-all|
                                       # restart|status|start-dedicated), prep, run
```

`python3 -m cmdscripts.manage_test_servers` keeps working via a
two-line forwarder left in place; the cwd-dependence of §2.1 disappears
for the entry-point form.

#### 9.2.7 Asset locator (adapter `data/`, TS-6)

```python
def asset(relpath: str) -> Path:
    """Resolve a suite asset (configs/…, fixtures/…, golden/…).
    Phase 1: resolves into the tests/ tree. A later physical move changes
    only this function — and a K8sBackend materializes the same manifest
    as ConfigMaps."""
```

### 9.3 What deliberately does NOT move

- All 1,165 test modules and `_test_*_helpers` shards;
  `split_continuation.reexport` stays functional indefinitely (TS-7 tail).
- `tests/configs/`, `fixtures/`, `golden/` physical location through TS-5.
- `run_multiuser_authz.sh`, sudo/privileged flows, `k8s-tests/`.
- Repo-root `utils/make_proxy.py` / `make_token.py` (used by non-suite
  tooling too); `brix_suite.security.proxy` wraps, does not move them.

### 9.4 The public surface, enumerated

The C3 versioning policy needs an object to version. This is it — the
core package's `__all__`, per module, collecting every API the F-specs
define (the generated reference of C5 is produced from these; a name
absent here is private regardless of spelling):

| Module | Exports (the 1.0 candidate surface) |
|---|---|
| `brixtest.fleet.registry` | `InstanceSpec` (incl. `to_dict`/`from_dict`), `Registry` (incl. `validate`), `ServerEndpoint`, `endpoint_for` |
| `brixtest.fleet.kinds` | `KindProfile`, `register_kind`, `get_kind`, `known_kinds`, `clear_kinds` |
| `brixtest.fleet.launcher` | `FleetPlan`, `SpecOutcome`, `StartReport`, `FleetLauncher` (`start_registered`, `stop`), `default_workers` |
| `brixtest.fleet.probes` | `TcpProbe`, `CommandProbe`, `AllOf`, `NoProbe`, `probe_from_alias`, `READINESS_ALIASES` |
| `brixtest.fleet.prep` | `FleetPrep`, `PrepStep`, `ArtifactSet` |
| `brixtest.fleet.declares` | `DECLARE_MARKERS`, `TestUsage`, `DeclarationMap`, `analyze_source` |
| `brixtest.fleet.orphans` | `Orphan`, `find_orphans`, `owns`, `reap` |
| `brixtest.harness.plugin` | `HarnessConfig`, `FleetHandle`, `activate` |
| `brixtest.harness.sentinel` | `StabilityPolicy`, `FleetSentinel` |
| `brixtest.config` | `Lane`, `OwnershipRecord`, `PortLedger`, `env_str`/`env_int`/`env_float`/`env_bool`, `install_legacy_module` |
| `brixtest.clients` | `WorkerRunner`, `serve` (`.procworker` adds `DEFAULT_TIMEOUT`) |
| `brixtest.deploy` | `DeployBackend` (`.local` adds `LocalBackend`) |
| `brixtest.util.configtext` | `render_cfg`, `render_cfg_strict`, `unresolved_placeholders` |
| `brixtest.events` | `Event`, `configure`, `emit`, `event_log_path` |
| `brixtest.testing` | `check_kind_contract`, `check_backend_contract` |
| `brixtest.stubs` | `StubServer`, `Response` (`.origin` adds `OriginStub`) |
| `brixtest.errors` | `BrixTestError` + the full C1 taxonomy |
| `brixtest.cli` | `main` (the `brixtest` entry point) |
| `brixtest.services.artifacts` | `ArtifactCatalog` (`publish`, `path`, `names`, `describe`) |
| `brixtest.services.logs` | `LogView` (`mark`, `lines`, `grep`, `tail`, `wait_for`), `LogMark` |
| `brixtest.services.workspace` | `WorkspaceAllocator` (`for_test`, `fresh`, `sweep`) |
| `brixtest.services.waiting` | `wait_until` |
| `brixtest.services.payloads` | `Payload`, `make_payload`, `verify_payload` |
| `brixtest.results.model` | `PhaseResult`, `TestRecord`, `RunInfo`, `Sample`, `Finding`, `OUTCOMES` |
| `brixtest.results.store` | `ResultStore` (incl. `export_opensearch`) |
| `brixtest.results.collector` | `ResultCollector`, `new_run_id` |
| `brixtest.results.report` | `write_report`, `write_index`, `serve` |
| `brixtest.fleet.dynamic` | `DynamicFleet`, `DEFAULT_DYNAMIC_OFFSET` |
| `brixtest.harness.resources` | `ResourcePolicy`, `ResourceWatch` |

Twenty-nine modules, roughly a hundred names — deliberately small against
the ~15k-LOC framework it fronts. Everything else is implementation,
free to move; this table is what a fixture rename or exit-code change
is measured against when C3 asks "was that a major bump?"

---

## 10. Migration Strategy — Shim Mechanics (the part that makes G5 true)

### 10.1 The prime directive

Every phase lands in three beats: **(a)** add a guard/test pinning current
behavior, **(b)** introduce the new home with the old name forwarding to
it, **(c)** flip the implementation. Import rewrites in test files are
never a prerequisite.

### 10.2 Single-instance modules and the aliasing shim

These modules hold process-wide mutable state and MUST exist exactly once:

| Module | State |
|---|---|
| `server_registry` | `_SPECS`, `_COMMAND_SUITES` |
| `conftest` (+parts namespace) | `_pytest_config`, `_test_tree_wiped`, sentinel/watchdog state |
| launcher instances | `_external_stops`, `_xrootd_procs`, manifests |
| `settings` | the 258 constants tests compare against |
| `fleet_prep` | (stateless today — keep it so) |

Therefore shims **alias, never re-execute**:

```python
# tests/server_registry.py  (after TS-4) — the whole file:
"""Legacy flat-import shim. Canonical: brixtest.fleet.registry."""
import sys
import brixtest.fleet.registry as _canon
sys.modules[__name__] = _canon          # one module object, two names
```

For `settings` the shim additionally freezes the import-time contract:

```python
# tests/settings.py  (after TS-3) — sketch:
import sys
from brix_suite.settings import SuiteSettings
from brixtest.config.settings import install_legacy_module
install_legacy_module(sys.modules[__name__], SuiteSettings.from_env())
# install_legacy_module sets all 258 names as module attributes and
# registers the instance as the process default.
```

Proof obligations, each backed by a new unit test (3-per-change rule):

1. **Identity:** `import settings; import brix_suite.settings as s2;
   assert settings.TEST_ROOT is s2 default's test_root` — and for aliased
   modules, `sys.modules["server_registry"] is
   sys.modules["brixtest.fleet.registry"]`.
2. **Completeness:** every name in the TS-0 surface inventory resolves on
   the shim (`shim-completeness` guard, §12).
3. **Order:** importing the shim first vs the package first yields the
   same object (both directions tested).

### 10.3 Import-order and env-at-import preservation

The `settings` shim keeps constructing `from_env()` at import time until
TS-7; the packages' own modules never read env at import. `pythonpath =
tests` stays for the whole migration — the packages coexist with the flat
namespace, and the aliasing pattern guarantees the two spellings are one
module.

### 10.4 Shim lifecycle

A shim is removable only when the TS-0 inventory shows zero remaining
importers of the flat name (post-TS-7 tranches). Until then shims are
frozen files with a guard forbidding edits except the alias target.

---

## 11. Migration Phases (detailed)

Every phase ends with the same **standing acceptance gate** (§14 runbook):
collect clean at current speed (±10%), one full real-fleet file green in an
isolated lane, `manage_test_servers start-all/stop-all` round-trip, all
suite-touching guards green, conservation check clean (no leaked
processes/listeners), xdist smoke (`-n 2`) green.

Phases land **parity surfaces only** (§7.3): each phase below lists the
feature specs whose parity it delivers. The *additive* halves of those
specs (F3's plan/report objects, F5's `gate explain`, F8's `lane
status`, all of F15, …) are never part of a migration commit — each
lands after its feature's parity phase has soaked, as its own gated
commit with its own test triad (risk R13). This split is what keeps NG2
("no behavior change") checkable: a parity commit's diff may contain
moves and shims, never new surface.

**Phase dependency structure** (arrows = hard precondition; TS-5 clusters
are mutually independent):

```
TS-0 ──► TS-1 ──► TS-2 ──► TS-3 ──► TS-4 ──► TS-6
 (charter) (pkg)  (harness) (config) (fleet)  (assets)
                              │        └──► TS-5 ◄──┐
                              │        security · clients · servers ·
                              │        mesh · perf · interop · cachemx ·
                              │        util · guards · cli · _legacy
                              │              │
                              └──────────────┴──► TS-8 (hygiene)
                                    TS-7 (optional test-side tail,
                                    unscheduled; needs TS-1…TS-6 soak)
                                    TS-9 (future k8s backend; needs TS-4
                                    seam + separate approval)
```

**Effort and commit-count estimates** (planning figures, not commitments;
one "commit" = one gate-passing, independently revertable landing):

| Phase | Commits (est.) | Effort | Dominant cost |
|---|---|---|---|
| TS-0 | 2–3 | ~1 day | writing + verifying the inventory script |
| TS-1 | 2–3 | ~1 day | dependency-pin archaeology across `requirements*.txt` |
| TS-2 | 6–8 (one per conftest part + activation + markers) | 3–5 days | verbatim-move review; xdist soak time |
| TS-3 | 4–6 | 2–4 days | `PortLedger` design + the 178-name shim proof |
| TS-4 | 8–12 (one per kind-ladder flip + module moves + backend seam) | 4–6 days | launcher soak (3× boot/stop cycles ≈ 10 min each) |
| TS-5 | 10–15 across 11 clusters | 5–8 days, parallelizable | tokenforge/x509forge dissolution review |
| TS-6 | 3–4 | 1–2 days | template-manifest guard |
| TS-7 | ~25 tranches × 1 | unscheduled | mechanical churn + review |
| TS-8 | 2–3 | ~1 day | lint-config graduation |
| TS-9 | design doc first | unscheduled | k8s backend MVP scoping (§15) |

---

### TS-0 — Charter and surface inventory (docs + one script; no product code)

**Objective.** Freeze the plan; make the shims verifiable before any exists.

**Work items.**
1. Land this document.
2. Write `tools/ci/dump_suite_surface.py` (stdlib `ast` only): for each of
   the 88 infra modules + `lib_py/*` + `conftest*`, emit (a) its public
   defs/classes/assignments, (b) every `import X` / `from X import Y` of a
   flat infra name found in all 1,255 `tests/*.py` + `cmdscripts/` +
   `resilience/` + `cvmfs/` + `unit/`, keyed by importer. Output:
   `docs/refactor/testsuite-surface-inventory.md` (tables) + a JSON sidecar
   the shim-completeness guard will consume. Draft skeleton (the real
   script lands with its own 3 tests — success on a fixture tree, error
   on a syntax-broken module, negative: an `exec`-only name like
   `fleet_specs_part2._data` must be reported as *shard-implicit*, not
   public):

```python
#!/usr/bin/env python3
"""Emit the flat-import surface of tests/ infra as JSON + markdown."""
import ast, json, sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2] / "tests"
INFRA = sorted(p.stem for p in TESTS.glob("*.py")
               if not p.stem.startswith(("test_", "_test_")))
PACKAGES = ("lib_py", "cmdscripts", "lib")

def public_surface(path: Path) -> dict:
    tree = ast.parse(path.read_text())
    out = {"functions": [], "classes": [], "constants": [], "shard_loads": []}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef): out["functions"].append(node.name)
        elif isinstance(node, ast.ClassDef): out["classes"].append(node.name)
        elif isinstance(node, ast.Assign):
            out["constants"] += [t.id for t in node.targets
                                 if isinstance(t, ast.Name) and t.id.isupper()]
    # names only defined when exec'd into a parent (shard-implicit) are
    # found by diffing against a plain importlib load attempt — see tests.
    return out

def importers(all_py: list[Path]) -> dict:
    """{infra_name: {importer_relpath: [imported_names]}} for every
    `import X` / `from X import a, b` where X is flat infra."""
    ...

def main() -> int:
    surface = {m: public_surface(TESTS / f"{m}.py") for m in INFRA}
    edges = importers(sorted(TESTS.rglob("*.py")))
    json.dump({"surface": surface, "importers": edges},
              open(sys.argv[1], "w"), indent=1, sort_keys=True)
    # + render the .md tables; exit non-zero if re-run diffs (idempotence)
    return 0
```

3. Decide the §15 open questions that gate TS-1 (name spellings;
   pytest.ini location — recommendation: keep root `pytest.ini`).

**Deliverables.** This doc; inventory doc + JSON; a decision note appended
here.
**Acceptance.** Inventory JSON round-trips (script re-run is a no-op diff);
doc guards green.
**Effort:** S. **Risk:** none. **Rollback:** delete docs.

---

### TS-1 — Packaging skeleton (additive only)

**Objective.** `pip install -e BriXTest/` exists; nothing depends on it yet.

**Work items.**
1. `BriXTest/pyproject.toml` — full draft:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "brixtest"
version = "0.1.0"
description = "BriXTest: generic server/client test config, deployment, and management (pytest-native), plus the nginx-xrootd suite adapter"
requires-python = ">=3.9"
dependencies = [
  "pytest>=9,<10", "pytest-xdist>=3.8", "pytest-timeout>=2.4",
  "pytest-rerunfailures>=16", "requests", "urllib3",
]
[project.optional-dependencies]
crypto = ["cryptography>=42"]     # tokenforge/x509forge/JWKS
s3 = ["botocore>=1.43.66,<2"]     # matches repo requirement pins
k8s = []                          # reserved for TS-9 (client libs TBD)
dev = ["ruff", "mypy"]
[project.scripts]                  # inert until TS-5 wires the modules
# brixtest = "brixtest.cli.main:main"
[tool.hatch.build.targets.wheel]
packages = ["src/brixtest", "src/brix_suite"]
```

   (Exact pins copied from `requirements*.txt` at land time; the extras
   split mirrors which suites die vs skip when the dep is absent —
   `fleet_prep` already tolerates missing `cryptography`.)
2. `src/brixtest/__init__.py` + `src/brix_suite/__init__.py` with
   `__version__` and an import-side-effect unit test (`import brixtest`
   mutates neither env nor `sys.modules` beyond itself).
3. CI: add `pip install -e BriXTest/` to the suite lanes next to existing
   installs; `check_python_deps.py` learns `pyproject.toml` as a manifest
   source (guard update #1, §12).
4. `BriXTest/README.md` stub pointing at this plan; settle both package
   spellings against `check_brix_namespace.py`.

**Explicit non-actions.** `pythonpath = tests` untouched; no module moved.
**Tests (3).** import-purity test (success), pip-install-in-clean-venv CI
step (error surface: missing dep pin fails the lane), a guard negative:
`check_python_deps` fails when a dep exists in package but not manifest.
**Effort:** S. **Risk:** low. **Rollback:** delete `BriXTest/`, revert CI
line.

---

### TS-2 — Harness extraction (the pytest plugin)

**Objective.** All hook logic of §5.1 lives in `brixtest/harness/`;
`conftest.py` becomes activation + re-export; `split_continuation.load`
gone from the conftest constellation. Highest-leverage, highest-care phase.
**Features (parity):** F5 (declaration gate), F6 (stability machinery),
F10 (plugin + fixture surface).

**Preconditions.** TS-0 inventory (which names tests import from
`conftest` — measured zero, §2.5); TS-1 package installed in CI.

**Work items (one commit each, gate after each).**
1. Create `harness/session.py`: move `_setup_session` + helpers from
   part2 and conftest.py into `SessionLifecycle` — method bodies verbatim,
   `settings` still imported flat (settings moves in TS-3, NOT here; one
   variable at a time). Suite-specific steps (data seed, `freeze_nginx`)
   are invoked through the adapter-configuration object from day one so
   the core file never names nginx.
2. Create `harness/gate.py`: move part3's declaration gate + persistent
   cache. Its existing unit tests (`test_conftest_fleet_lifecycle.py`
   declare-cache quartet) are repointed via shim only — test files
   unedited, `conftest` re-exports the moved names.
3. Create `harness/sentinel.py`: part4 verbatim.
4. Create `harness/fixtures.py` + adapter `harness_ext.py`: the 15
   fixtures (core mechanics vs suite-specific refs per §9.2.5).
5. Create `harness/plugin.py` defining every hook as one-line delegations;
   `tests/conftest.py` drops the four `_load_continuations` targets one at
   a time (part4 first — no hooks, lowest risk; then part3, part5, part2),
   each replaced by explicit re-exports. In the same step, consolidate
   marker registration: the 4 dynamically-registered markers of
   `conftest_part3.py:129-156` (§5.9) move into the plugin's
   `pytest_configure`, ending the two-homes split with `pytest.ini`.
6. Only after all four: switch activation to
   `pytest_plugins = ["brixtest.harness.plugin"]`; conftest keeps
   rootdir-specific residue (lane refusal message, `_ORIG_CWD` capture)
   until TS-3 relocates it.
7. Delete `conftest_part2–5.py` (contents fully absorbed); keep
   `conftest_mu.py` as shim to the adapter's `harness_ext`.

**Ordering invariants to preserve (checked by tests):** worker/collectonly
early returns stay the first statements of their hooks; `pytest_configure`
TMPDIR pinning still runs on every xdist worker; sessionfinish order
conservation → sweep → alarm → destruction; `_pytest_config` single
instance (§10.2).

**Tests (3 minimum, more in practice).** Success: full harness unit files
green via shims, unmodified. Error: a deliberately double-registered
plugin (entry-point + conftest) is detected and refused with a clear
message. Security-negative: the declaration gate still FAILS a test that
uses an undeclared server (run the existing gate-negative fixture) after
extraction — the gate cannot be silently disconnected by the move.
**Guard updates.** `check_file_size`/`check_complexity` see new package
files (both guards are path-agnostic ratchets — verify they scan
`BriXTest/src`; extend scan roots if not: guard update #2).
**Effort:** L. **Risk:** medium (R2). **Rollback:** conftest re-grows a
`_load_continuations` line per un-absorbed part; parts are restorable from
git history at any granularity.

---

### TS-3 — Configuration object

**Objective.** `SuiteSettings`/`Lane`/`PortLedger` land; `tests/settings.py`
becomes the §10.2 shim; the 690 dependents observe identical values.
**Features (parity):** F8 (lanes + port ledger); the C2 configuration-
precedence contract (§7.5) becomes enforceable from here on.

**Work items.**
1. `brixtest/config/ports.py`: `PortLedger` machinery built from the
   current 258-constant inventory (TS-0 enumerates the exact port names);
   ladder math from `port_ladder.py`; consolidation design for the five
   `fleet_ports*` modules (own mini-design, §15 —
   `fleet_ports_shared_phase5.py` at 1,120 LOC is the one file above the
   size guard's grandfathered line). The concrete fixed-port tables land
   in `brix_suite/ports.py`.
2. `brixtest/config/settings.py`: dataclass machinery +
   `install_legacy_module`; `brix_suite/settings.py`: `SuiteSettings`
   per §9.2.1.
3. `brixtest/config/lanes.py`: lane ownership/refusal (text of the
   refusal message is user-facing in ops docs — moves byte-identical).
4. Shim `tests/settings.py` (§10.2); shim-completeness guard goes live
   against the TS-0 JSON (guard addition #3).
5. Harness plugin constructs the default instance at `pytest_configure`;
   everything else still reads the legacy module (no dependent changes).
6. Validation warn-only: any refusal that today does not fire may only
   log for one full phase.

**Tests (3).** Success: identity + completeness proofs of §10.2 as unit
tests; `from_env`/`derive` lane math against the documented
`TEST_ROOT`/`TEST_PORT_START` matrix. Error: malformed env (non-int port
base) produces the same failure mode as today (import error text
compared). Security-negative: foreign-lane refusal still triggers on a
port owned by a live foreign listener (existing lane-refusal test re-run
through the shim).
**Effort:** M. **Risk:** medium (R3). **Rollback:** shim repointed at the
archived original `settings.py` body (kept as
`brix_suite/_legacy/settings_flat.py` until TS-7).

---

### TS-4 — Fleet core and the deployment seam

**Objective.** Registry, specs, catalogue, launcher (mixins dissolved),
prep, declares, orphans, port modules move; `KindProfile` replaces kind
ladders; the triplicated nginx helpers become one module; the
`DeployBackend` interface is cut with `LocalBackend` as its only
implementation (§8).
**Features (parity):** F1 (specs/registry), F2 (kind profiles), F3
(orchestration engine), F4 (probes/endpoints), F7 (artifact pipeline),
F9 (`LocalBackend`). The F15 event skeleton may land immediately after
this phase soaks (additive, its own gate).

**Work items.**
1. `brixtest/fleet/registry.py` ← `server_registry.py`; alias shim
   (§10.2 — the 330 dependents and the `_SPECS` singleton make aliasing
   mandatory). `InstanceSpec` is the canonical name;
   `NginxInstanceSpec = InstanceSpec` alias preserved.
2. `brixtest/fleet/specs.py` ← dataclasses + `KindProfile` mechanism;
   `brix_suite/kinds.py` ← the six rows + starters/renderers (§9.2.2).
3. `brix_suite/nginx_tools.py` ← ONE copy of the triplicated helpers; the
   duplication disappears from `check_duplication`'s blind spot.
4. Launcher modules ← mixins a/b/c verbatim; assembly + facade; errors.
   In the same cluster, cut `brixtest/deploy/backend.py` and move the
   fork/exec-pidfile-ports mechanics into `deploy/local.py`
   (`LocalBackend`) — a file move plus interface conformance, no
   behavior change; the §8.4 rules become review checklist items here.
5. Kind-ladder → `KindProfile` flips ONE ladder per commit (start
   dispatch, `stop`, `_quiescent`, `_stop_from_disk`), each pinned by the
   existing contract tests (§9.2.2) before and after.
6. `brixtest/fleet/prep.py` ← `FleetPrep` engine, `brix_suite/prep_steps.py`
   ← the steps (§9.2.4); `fleet/declares.py`, `fleet/orphans.py` verbatim
   moves with alias shims (`fleet_orphans.owns` is imported by two CLIs
   per history §10 — inventory-checked).
7. `brix_suite/catalogue.py` ← `fleet_specs.py` + `fleet_specs_part2.py` +
   `fleet_values.py` (three modules, one namespace, no exec). This
   dissolves the `fleet_specs.py:405` exec and fixes the measured
   standalone breakage of §2.3 (`fleet_specs_part2.ha_specs()`
   NameError on `_data`) as a side effect; the pin is a new unit test
   asserting `catalogue.ha_specs()` works under plain import.
8. Ports consolidation per TS-3's mini-design (`brix_suite/ports.py`
   absorbs `fleet_ports*.py`).

**Soak.** Beyond the standing gate: 3× consecutive full-fleet
boot/stop cycles in an isolated lane (`TEST_ROOT=/tmp/xrd-test-ts4-lane`,
fresh `TEST_PORT_START`), zero leaked listeners between cycles, plus the
`manage_test_servers status` snapshot identical before/after.

**Tests (3).** Success: launcher contract suite green through shims
unmodified. Error: stop-failure test (one spec's stop raises → every
other spec still visited). Security-negative: `_quiescent` never
short-circuits an `external` spec or one in `_external_stops` (i.e. the
fast path cannot skip stopping something we do not own — this is the §14
lane-safety property).
**Effort:** L. **Risk:** medium-high (R4). **Rollback:** per-commit; alias
shims mean any partially-landed state still imports.

---

### TS-5 — Security, clients, servers, mesh, perf, interop, CLI, legacy

**Objective.** Remaining infra moves by cluster into the adapter (core
promotions only per §7.2); entry points go live; bash-era survivors are
quarantined.
**Features (parity):** F11 (client drivers), F12 (stub servers), F13
(templating mechanics), F14 (CLI).

**Clusters (independently landable, in any order).**
- **security/**: tokenforge 4-mixin dissolution mirrors TS-4 step 4
  (same verbatim-bodies rule; token vector tests are the pin); x509forge
  parts likewise; `pki.py` takes `pki_helpers` alone; `kdc.py` takes
  `kdc_helpers` — note it is started as a *script by absolute path* from
  the spec catalogue, so its entry point has to survive in the shim too.

  The three Layer-3 differential drivers land beside their forges as
  `tokens_vectors`, `x509_vectors` and `x509_matrix_vectors`. *Three
  modules, not the two the mapping table planned:* the two x509 drivers
  share a shape and nothing else — one replays named hostile scenarios
  against a fresh `WlcgInstance` per credential, the other replays the
  clause matrix against a single `ConformanceFleet` — so merging them
  would have produced one module with two disjoint halves and two
  FINDINGS paths. Each is invoked **by absolute path** from a
  `cmdscripts` runner whose pytest wrapper SKIPs unless `TEST_TOKEN_DIFF`
  / `TEST_X509_DIFF` is set, and each `__main__` block carries real logic
  (argv parsing plus the exit code the tier asserts with). That is the
  worst possible place for a stranded entry point — it fails green — so
  every one becomes a named `main(argv=None)` the shim calls, and guard
  #11 pins the property for the whole shim set.

  *The "merge three `regenerate_pki`s" premise was wrong and is retired.*
  The inventory read three same-named things as one duplicated function.
  Measured against the code, they are three different functions with three
  different fates:

  | spelling | what it is | fate |
  |---|---|---|
  | `pki_helpers.blitz_test_pki` | the actual generator: CA, host + user certs, hash links, signing policy, then `make_proxy.py` and `make_crl.py` | **moved** to `brix_suite.security.pki`; flat spelling stays a live shim |
  | `lib_py/pki.regenerate_pki` | out-of-process wrapper (`python -c` + `PYTHONPATH=tests`) that *also* mints proxies, no fault tolerance; ships alongside a 30-entry `DEFAULTS` port table and `substitute_config` | **`_legacy/`** — its only consumers are `cmdscripts/pblock_live{,_part2}`, `lib_py/nginx` and `lib_py/dedicated`, and `dedicated.py` is already `_legacy`-bound at TS-5 |
  | `prep_steps.regenerate_pki` | in-process, fault-tolerant (`warn and continue`, mirroring the bash), makes the subdirs first, does *not* mint proxies itself | **stays put** — monkeypatched at 5 sites across 2 pinning files, which NG1 puts out of reach until TS-7 |

  They are not interchangeable: different signatures, different failure
  policy, different outputs.  Merging them would have meant choosing one
  behaviour for callers that depend on the others.

  `mint_delegation_certs.py` does not join `pki.py` either — it is a CLI
  read off `sys.argv` and invoked by *path* from `cmdscripts`, not a
  library.  It belongs to the `cli/` cluster.

  Two defects surfaced while measuring this, both fixed with the move:
  `prep_steps.regenerate_pki` claimed `blitz_test_pki` "keys off `PKI_DIR`
  in the environment" — it does not, `settings.PKI_DIR` is `TEST_ROOT/pki`
  fixed at import, so the env dance steered nothing (it now warns when the
  requested and actual targets diverge); and the fleet-prep cache was
  stamping `tokenforge.py`, which the earlier TS-5 move had turned into a
  shim, so edits inside `security/tokens/` no longer busted the cache.  See
  guard-adjacent pin `test_ci_ts5_generator_stamps.py`.
- **clients/** *(landed)*: the grown XrdCl layer splits into
  `brix_suite.clients.xrdcl.{worker_link,results,proxies,worker}` behind a
  facade; `http.py` and `gridftp.py` stay adapter; `pty.py` promotes to
  `brixtest.clients.pty`. Six flat modules become §10.2 shims, six bodies
  archive to `_legacy/`, and 49 definitions move with zero lost, zero extra
  and zero differing AST body hashes.

  *The "port the proxy onto `procworker`" premise did not survive contact
  with the code and is retired.* `brixtest.clients.procworker` (F14) does
  deliver the generic tag-correlated protocol, but the grown proxy carries
  four affordances the generic one deliberately lacks — environment resync
  when the caller changes `X509_*` mid-session, GC-safe lock-free handle
  release, per-op timeout widening, and re-raising the binding's *native*
  builtin exception type. Rewriting the layer onto the generic protocol
  would have been a behaviour change against R10 and against the
  verbatim-bodies rule, so the two protocols coexist: `procworker` is what a
  second consumer writes, `xrdcl` is what this one already runs.

  **The split had to answer a question the earlier clusters never asked:
  what happens when the module being split owns mutable process state.**
  This layer keeps a single worker subprocess per pytest process in a module
  global, guarded by a module lock and torn down by a module `atexit` hook —
  so `worker_link` owns the singleton and the facade must never copy it. A
  `from … import _worker_singleton` in the facade freezes `None` at import
  while the owner rebinds it on first use; every later reader of the flat
  spelling then sees a worker that does not exist. The only truthful
  spelling is a module `__getattr__`, which by construction never appears in
  `__dict__` — so guard #3's probe moved from `vars(mod)` to `dir(mod)`.
  That is the guard being made honest, not weakened: `vars()` would have
  rejected the one correct facade and accepted the stale copy.

  The worker script path is data the package carries, and getting it wrong
  **fails green** — no exception, the interpreter probe simply finds no
  candidate, `real_bindings_available()` returns False, and nine XrdCl
  suites SKIP. Same failure class as the stranded `__main__` blocks of the
  security cluster, so it is pinned the same way: an explicit test asserts
  the package starts the script it ships.
- **servers/** *(landed)*: `tests/lib/*.py` one-to-one — seven stub
  processes plus `tokenconf`, the WLCG conformance library twenty-five
  suites import. 36 top-level definitions (57 counting methods) moved with
  zero drift; eight §10.2 shims stay at `tests/lib/`, because that is the
  spelling those suites and two `cmdscripts` drivers already use.

  Two deviations from verbatim, both forced by the destination. Five
  modules opened with `sys.path.insert(0, dirname(dirname(__file__)))`
  purely to reach `settings`; two parents of `tests/lib/` is `tests/`, two
  parents of `brix_suite/servers/` is `brix_suite`. The line could not stay
  — and would not have raised if it had, since the directory it names
  exists. It is gone, `from settings import` became
  `from brix_suite.settings import`, and the `import os`/`import sys` the
  line had been the last user of went with it.

  The four catalogue `proc` specs switched together rather than one per
  commit. The original phrasing assumed the specs were independent; they
  share `_module_env()`, and the reason is the switch itself. A path spawn
  puts the *script's* directory on `sys.path[0]`, which is what made the
  self-locate work; `-m` puts the *current* directory there instead. So
  every module spec has to name `tests/` explicitly via `PYTHONPATH` or the
  child dies on `ModuleNotFoundError` before it binds. `_module_env()`
  prepends rather than assigns — a lane may already be running with a
  `PYTHONPATH` of its own, and clobbering it would break the run somewhere
  else entirely.

  The designed `StubServer` base (F12) is **not** retrofitted onto these
  seven. It already exists in core, with the lane-refusal this phase's
  security-negative asks for; but these stubs are pinned by suites that
  read their exact wire responses, so rewriting them onto the base would be
  a behaviour change wearing a refactor's clothes. The base is what the
  *next* stub is written on. The security-negative is therefore proven
  twice: `brixtest.stubs.StubServer` refuses a port outside its lane and a
  non-loopback bind (exit 2, one line), and a static scan proves none of
  the seven moved stubs binds a wildcard address.
- **mesh/** (DELIVERED): nine modules one-to-one — `cms_mesh_lib` and its
  two continuation shards, `hybrid_mesh_lib`, `mesh_config`, the two
  `*_servers` orchestrators, and the two WLCG fleets. Both `__file__`-hop
  path derivations are replaced by `brix_suite.settings.TESTS_DIR`; both
  had resolved, from the new location, to a directory that **exists**, so
  the failure would have been a silently skipped sss topology rather than
  an ImportError. The catalogue's two mesh specs switched to `-m` and
  gained `_module_env()` with them. The planned rename to `.cms`/`.hybrid`
  /`.wlcg` is deferred — see the note under the Appendix A rows.
- **cachemx/** — DELIVERED. Five modules, same shape of hazard as mesh
  and found the same way: `_cachemx` and `_cache_partial_helpers` each
  derived the repo two parents up to reach `client/bin/`, which from
  `tests/brix_suite/cachemx/` lands on `tests/brix_suite` — a directory
  that exists. `_require_binaries()` would have skipped ~30 suites with
  "native client binary missing", reading as an unbuilt client. Both now
  come from `settings.TESTS_DIR`. The two catalogue snapshots are pure
  data, so the gate checks them against each other (HELP and LABEL_KEYS
  cover one family set, CONDITIONAL is a subset) — a truncated copy passes
  every other check in the file.
- **perf/** — **DELIVERED.** Four modules moved: the load driver
  `load_test` with its two exec-composed shards, and the A/B throughput
  measurer `_perf_ab_helpers`. The driver's entry point was a `__main__`
  guard at the foot of shard 3, firing on the *parent's* `__name__`; a
  package module is never named `"__main__"`, so it became `run_cli()`
  called from the shim. **`_perf_netem_helpers` stayed flat**, and the
  reason is a guard rather than a preference — see the Appendix A row and
  the Appendix E entry. Leaving it behind is only safe because of the
  shim: its `--measure` child does `sys.path.insert(0, dirname(__file__))`
  then `from _perf_ab_helpers import …`, and that `dirname` is still
  `tests/`. One declared deviation from verbatim, `from __future__ import
  annotations` on shard 2, because `Suite.run_one` is annotated
  `-> RunStats` and evaluated it eagerly — which made the shard
  unimportable standalone and so unable to be a shim at all.
- **interop/**, **util/**, **guards/** per the Appendix A map;
  `util/` is split by topic, explicitly not a grab-bag. Note for the
  interop step: `interop` is itself a `_SLOW_MODULE_HINTS` substring, so
  its gate file must not be named `test_ci_ts5_interop_move.py` until the
  TS-7 classifier fix lands — see the mesh entry in Appendix E.
- **cli/**: the `brixtest` entry point goes live (§9.2.6);
  `cmdscripts/manage_test_servers.py` becomes a forwarder;
  `python3 -m cmdscripts.…` from `tests/` keeps working (test asserts
  both invocation forms produce identical `status` output).
- **_legacy/**: `lib_py/dedicated.py` moves with a module-level
  `DeprecationWarning`; new guard blocks new imports of `_legacy` outside
  `_legacy` and existing users (guard addition #4).

**Tests.** 3-per-cluster minimum following the TS-4 pattern; the
security-negative for `servers/` is that a stub server refuses to start
outside a lane root (no accidental bare-/tmp listeners).
**Effort:** L, parallelizable. **Risk:** medium. **Rollback:** per cluster.

---

### TS-6 — Assets

**Objective.** One locator API fronts every asset; physical moves become
reversible decisions instead of big-bang churn.
**Features (parity):** F13's asset-manifest half (guard #5); prerequisite
for F13's strict-mode addition (the deliberate-brace whitelist is
inventoried here).

**Work items.**
1. `brix_suite/data/__init__.py::asset(relpath)` (§9.2.7) resolving into
   `tests/` initially.
2. Mechanical migration of infra consumers (launcher `render_nginx`
   template lookup, fixture seeds) to `asset()` — test files untouched
   (they reach templates via the launcher).
3. `check_template_refs.py` extended: every template referenced via
   `asset()` exists; every template in `configs/` is referenced or
   explicitly whitelisted (guard update #5).
4. Physical move decision (move vs stay) taken per asset class on churn
   evidence; a move flips only `asset()`'s root.

**Effort:** M. **Risk:** low. **Rollback:** `asset()` root repoint.

---

### TS-7 — Test-side tail (OPTIONAL, separately approved, not scheduled)

Tranche-wise (`~50` files per tranche, mechanical rewriter + review),
with a designated first tranche: the harness pinning suite's by-path
conftest loader (§5.10) converts to direct `brixtest.harness.*`
imports, deleting the last institutionalized dual-identity load. Then:
flat imports in test files → `brixtest.…`/`brix_suite.…`; retire
`split_continuation.reexport` per split-suite by converting helper shards
to real modules; remove shims whose importer count (per re-run TS-0
inventory) reaches zero; last of all, drop `pythonpath = tests` and move
pytest config into `pyproject.toml` if §15's decision so chooses. Each
tranche passes the standing gate. This phase is deliberately unscheduled:
it is 1,165 files of churn that only pays off after TS-1…TS-6 soak.

**Carried in from earlier phases** (recorded where the work is allowed, not
where it was found):

- **Make `serial` authoritative under `--dist=loadgroup`.** `conftest_part3`
  adds `pytest.mark.xdist_group("serial")` in `pytest_collection_modifyitems`,
  which each *worker* runs, while the controller's loadgroup scheduler keys on
  the `@group` suffix in the nodeid -- so the marker is invisible when the
  split is decided and **every `serial`-marked module in the suite can be split
  across workers**. conftest already appends the suffix by hand for
  `cvmfs-fixed-ports` and `ci-guards`; `serial` needs the same three lines.
  Measured 2026-08-18 by `test_ci_ts3_settings_live_lane.py`, whose 13 tests
  landed on gw0 and gw1 and booted the same lane twice: one fixture wiped
  `pki/` while the other generated into it, and the boot died on a half-built
  CA with **no warning from either side** -- the artifact sentinels are checked
  when a snapshot is *stored*, not after generation, so an incomplete tree
  passes through `prepare()` silently. That silence is worth a second fix here:
  `prepare()` should check `_missing_sentinels` after generating, not only
  before snapshotting. Until both land, a module that owns a lane must take an
  exclusive lock of its own (the live-lane file is the worked example).
- **Stop classifying tests as slow by their filename.**
  `conftest_part3._SLOW_MODULE_HINTS` is thirty-odd substrings matched against a
  module's *name*, and the PR gate runs `-m "not slow"`. At the mesh cluster
  (2026-08-19) `test_ci_ts5_mesh_move.py` matched `_mesh` and all forty of its
  tests were deselected while the gate set reported **`310 passed`** — a run
  that did nothing and said so in green. The classifier's comment says
  "over-inclusion is safe: the full suite run covers everything regardless",
  which is true of a *slow suite* wrongly excluded from the fast tier and false
  of a *gate*, whose entire job is to run in that tier. The gate file was
  renamed to `test_ci_ts5_cluster_move.py` because the conftest is pre-TS-4 and
  out of reach under NG1; `test_no_ci_gate_file_is_auto_marked_slow` (in that
  file, reading the hint tuple from the conftest rather than copying it) keeps
  the next one from landing in the same hole. The real fix here is to mark by
  something a file declares — a marker, a directory — rather than by what its
  name happens to contain.
- **Swap `test_fleet_liveness.py`'s sampler** from per-port `pids_on_port()`
  to a single `listening_port_pids()` survey per sweep. The §15 finding has
  the measurements: 756 `ss -ltnp` calls ≈ 310 s inside a 120 s budget, versus
  27.4 s for the survey path on the same fleet. `_classify` already takes a
  `{pid: age}` mapping, so the edit is confined to `_listeners_with_age` and
  `_live_fleet_ports`. Then audit the suite for the same per-port-in-a-loop
  shape — its cost only appears at fleet scale on a loaded host, exactly when
  a timeout gets re-run as a flake instead of diagnosed.
- **Convert `test_fleet_prep_cache.py` from monkeypatch-heavy to
  constructor-parameter tests** (§9.2.4), which is what lets `prepare()`'s
  snapshot cache become a `SnapshotCache` object instead of five module-level
  globals rebound by the test. TS-4 item 6 kept the flat-to-flat shim
  precisely so those five rebinds keep working until this lands.
- **Install the launcher shim.** `brix_suite/launcher/` is built, pinned and
  byte-for-byte equal to the flat stack (50 of 51 methods hash-identical; the
  one difference is `__init__`'s documented `TESTS_DIR` move-hazard fix), but
  it is deliberately **not wired in**: `server_launcher.py` is still the live
  module and no §10.2 shim points at the package. `test_server_registry_smoke.py`
  and `test_fleet_port_uniqueness.py` rebind `server_launcher.Path`,
  `.REGISTRY_STRICT_TEMPLATES`, `.subprocess.run` and `.socket.create_connection`
  in the launcher's module dict, which only resolves while the `exec`
  composition gives every method one shared globals dict; against a real
  package the rebind lands on the facade and the topic module keeps running
  the original. Install the shim and convert those four rebinds in the same
  tranche — the same patch-transparency property that kept `conftest.py`
  parts 2/3/5 exec-composed at TS-2. `test_ci_ts4_launcher_and_deploy.py`'s
  last test pins the not-installed state and is deleted by this step.

---

### TS-8 — Steady-state hygiene

- Suite-scoped `ruff` + `mypy` config in `BriXTest/pyproject.toml`
  (strict on new modules, graduated on moved ones).
- Guard additions live from earlier phases now enforced repo-wide:
  no-`split_continuation.load`-under-`BriXTest/src` (#6),
  no-new-flat-infra-imports in NEW test files (#7 — new files only;
  existing files exempt until their TS-7 tranche), import-direction
  guard `brixtest`-never-imports-`brix_suite` (#8).
- `BriXTest/README.md` full write-up; CHANGELOG discipline for any
  harness-visible change; version bumps on fixture/hook surface changes.
- **The additive tranche gate opens:** with every parity surface
  soaked, the §7.3 additive halves land one feature at a time, each
  with its own triad — and the §7.5 contracts become enforced review
  policy: `__all__` + `py.typed` complete (C3), no bare `RuntimeError`
  in core (C1), the F15 event schema stabilized v0 → v1 (C4), the four
  how-tos written (C5).

---

### TS-9 — Kubernetes backend (FUTURE; design doc first, separate approval)

Not part of this plan's deliverables; recorded so TS-4 cuts the seam in
the right place. Entry criteria: TS-4 landed and soaked; a dedicated
design doc answering the §15 k8s questions (client access path, image
strategy per kind, which spec subset an MVP covers — recommendation:
`proc` stubs + one nginx role first). Prior art: `k8s-tests/charts/`,
`k8s-tests/pki-scripts/`, `k8s-tests/remote-suite` (§8.3). Acceptance
shape: the SAME test file passes against `LocalBackend` and `K8sBackend`
with only a backend-selection knob changed.
**Features:** F9's `K8sBackend` + the `brixtest.testing.backend_contract`
conformance suite (F9's additive half) as its acceptance instrument.

---

## 12. Guard and Tooling Update Matrix

Measured 2026-08-17 (guards whose source mentions `tests/`):

| Guard | Current `tests/` coupling | Update phase | Change |
|---|---|---|---|
| `check_file_size.py` | scans `tests/`; backlog file paths | TS-2 | ensure `BriXTest/src` in scan roots; 600-LOC limit applies to package code from day one |
| `check_complexity.py` | scans `tests/` | TS-2 | same |
| `check_python_deps.py` | reads suite imports under `tests/` | TS-1 | learn `BriXTest/pyproject.toml` as a manifest |
| `check_template_refs.py` | template refs under `tests/` | TS-6 | route through `asset()` manifest |
| `check_ports_doc.py` | **hard-codes `tests/settings.py`**; requires every port constant by name in `docs/10-reference/test-fleet-ports.md` | TS-3 | read `PortLedger.iter_named_ports()` (single source) — this guard is the reason ports must stay enumerable, not computed |
| `check_doc_paths.py` | validates doc-referenced paths | TS-0+ | no code change; every phase keeps doc paths real |
| `check_config_coverage.py` | `tests/` refs | TS-4 | repoint launcher/template references |
| `check_client_build_coverage.py` | `tests/` refs | none expected | verify only |
| `check_brix_namespace.py` | brix naming rules | TS-1 | settle `brixtest`/`brix_suite` spellings against it |
| `guard_set.py` | orchestrates the above | each phase | runs the updated set |
| in-suite guards (`source_guards_lib`, notroot wire, cvmfs proxyabuse, declaration gate) | live in the suite itself | TS-4/5 | move with their subjects; path assumptions updated in the same commit |

New guards added by this plan: **#3 shim-completeness** (TS-3; consumes
TS-0 JSON), **#4 no-new-`_legacy`-imports** (TS-5), **#5 template-asset
manifest** (TS-6), **#6 no-exec-shards-in-package** (TS-8), **#7
no-new-flat-imports in new test files** (TS-8), **#8 import-direction:
`brixtest` never imports `brix_suite`** (live from TS-2, since the first
core module lands there), **#9 performance budgets** (TS-8), **#10
shard entry points** (added and wired in TS-5, unplanned), **#11 shim
entry points** (added and wired in TS-5, unplanned).

Guard #10 (`check_shard_entrypoints.py`) came out of the migration
rather than the design. A CLI written as `if __name__ == "__main__":`
at the foot of a shard runs only while that shard is `exec`-ed into its
parent's globals; converting the parent to a package leaves the guard
belonging to the shard, where it never fires. TS-5 hit this twice in
one afternoon, and the token-forge instance was invisible:
`prep_steps.FleetArtifactsStep` invokes that CLI with `tolerate=True`,
so the moved stack **exited 0 while writing no JWKS and no
scitokens.cfg**. A sweep found 13 further modules carrying the same
shape, every one of them correct today and every one of them a silent
break for whoever moves it. The guard therefore pins the *pairing* —
a shard holding a `__main__` guard must still be exec-composed — so it
stays quiet until exactly the moment someone needs telling. It is
adjacent to but narrower than the planned #6
(no-exec-shards-in-package), which outlaws the composition itself at
TS-8; #10 protects the years between now and then.

Guard #11 (`check_shim_entrypoints.py`) is #10's other half, and was
written the moment the differentials cluster made the exposure obvious.
Guard #3 proves a §10.2 shim still *exports* everything its flat body
did; nothing proved the shim still *runs* what its flat body ran. A
`__main__` guard is not a name — it is a property of how the
interpreter was started — so it does not survive the body moving into a
package the shim merely imports, and `python3 tests/x.py` quietly
becomes a script that exits 0 having done nothing. That matters most
where it is least visible: nine of these files are reached by absolute
path from a spec catalogue or a `cmdscripts` runner, and three of those
runners sit behind an opt-in env var whose pytest wrapper SKIPs, so a
stranded entry point is not a red test — it is a green one.

The check is archive-driven, which is why it can be honest: if
`_legacy/<x>_flat.py` carries a top-level `__main__` guard, the flat
stack *had* a CLI, so the live head of that stack must carry one that
still calls something. Both sides are read with `ast`, because every
shim in this cluster discusses `__main__` at length in its docstring
and a grep-based guard would pass on the prose. Shard archives are
charged to the module callers actually run (`x509forge_part3_flat.py` →
`tests/x509forge.py`), not to the shard that happened to hold the last
line.

**Its first run on the real tree found one.** `tests/fleet_prep.py` had
been a script since the bash fleet was retired — `prepare()` plus a
line operators grep for — and TS-4's move to `brix_suite.prep_steps`
left the guard in the package. From that commit until now, `python3
tests/fleet_prep.py` exited 0 having generated no PKI, no tokens and no
stage hook. Nothing referenced it in CI, which is exactly why it went
unnoticed for a phase and a half. Fixed the way the guard's own error
message prescribes: `prepare()`'s block became `prep_steps.main()`, and
both spellings call it by name.

**The clients cluster then found a defect in the guard itself.** Charging
a shard archive to the module callers run means stripping the shard
suffix — and the first implementation also stripped a leading underscore
unconditionally, because `_tokenforge_part2_mixina_flat.py` really is a
slice of `tests/tokenforge.py`. `_xrdcl_worker_flat.py` is not a slice of
anything: it is simply private, and its own stack head. The guard went
hunting `tests/xrdcl_worker.py`, found nothing, and reported a missing
entry point that had never existed — a false red on a file that was
correct. The underscore is now settled by asking the tree rather than by
guessing at the name: drop the shard suffix, take `<head>.py` if it
exists, and only then try the stripped spelling. Both shapes are pinned
by `test_ci_ts5_shim_entrypoint_guard.py`, since either one alone leaves
the other free to regress.

**Guard #3 changed in the same cluster, for a deeper reason.** Its probe
read `vars(mod)` — the module `__dict__` — which is correct for every
module whose surface is bindings. It is wrong for a facade over mutable
process state. The XrdCl layer keeps one worker subprocess per pytest
process in a module global; the facade cannot re-export that global by
value without freezing `None` at import while the owner rebinds it, so
the only truthful spelling is a module `__getattr__`, and a
`__getattr__` name never appears in `__dict__`. Under the old probe the
correct facade failed the guard and a stale copy passed it. The probe now
reads `dir(mod)`, which sees both. This is the guard's contract stated
precisely: it proves a name still *resolves* on the shim, not that it
still means what it meant — the latter is the pinning suite's job, and
`test_ci_ts5_clients_move.py` carries the assertion that the live state
is served rather than copied.

**Then the servers cluster broke the same probe a second way, and #11 a
second way, and the pattern is the point.** Both guards had been written
against a tree where every shim sat at the top of `tests/`. The eight stub
servers are shimmed at `tests/lib/`, and each guard took the same kind of
damage from that: guard #3's `__import__("lib.tokenconf")` hands back the
`lib` *package*, whose `dir()` is empty — so all 34 baseline names read as
dropped — and guard #11's head resolver only ever looked at
`tests/<name>.py`, so all eight archives read as CLIs whose stack head "no
longer exists". Two red guards, sixteen files, none of them wrong.

The fixes are one line each in spirit — `importlib.import_module` for the
first, a search over `("", "lib", "lib_py", "cmdscripts")` for the second
— but the shared lesson is worth more than either. A guard that computes
where a file *ought* to be is making a claim about the tree's shape, and
that claim expires the first time the tree grows a directory. Guard #11
now settles both of the things a name cannot answer — the leading
underscore and the directory — by asking the filesystem which spelling
exists. Both halves are pinned in
`test_ci_ts5_shim_entrypoint_guard.py`, separately: either alone leaves
the other free to regress back into arithmetic.

Guard #9 makes the history-§11 optimizations *policy* rather than a
high-water mark the migration could silently erode. Measured baselines
(2026-08-17) become CI ceilings with deliberate headroom — a budget
breach is a failed check, not a shrug:

| Operation | Measured baseline | CI budget |
|---|---|---|
| full-suite collection | 19.1 s | ≤ 30 s |
| single-file collection | 2.6 s | ≤ 5 s |
| warm `fleet_prep` | 0.02 s | ≤ 0.5 s |
| stop sweep, quiescent fleet | 0.15 s | ≤ 1 s |

The guard runs collect-only plus a warm-prep invocation in the
migration lane; budgets are ceilings, not targets, and tightening one
is a normal (minor) change while loosening one requires the same
justification as any contract change (C3).

---

## 13. Risk Register

| # | Risk | Phase | Detection signal | Mitigation | Rollback |
|---|---|---|---|---|---|
| R1 | Dual module identity (flat + packaged) → two registries / two configs; ImportPathMismatch redux | TS-2+ | identity unit tests (§10.2) fail; fleet half-boots; `sys.modules` audit fixture | aliasing shims only — re-execution banned by review checklist + shim-freeze guard | repoint alias |
| R2 | Hook ordering / xdist `workerinput` drift during harness extraction | TS-2 | `-n 2` smoke red; TMPDIR litter in bare `/tmp`; sentinel fires at session start | verbatim moves, one hook per commit, gate-per-commit; ordering invariants unit-tested | re-add `_load_continuations` for the offending part |
| R3 | `settings` import-time env contract breaks lane isolation | TS-3 | foreign-lane refusal stops firing, or fires falsely; lane matrix test red | shim preserves import-time `from_env`; warn-only validation for a full phase | shim → archived flat body |
| R4 | Mixin dissolution changes launcher behavior/MRO | TS-4 | contract tests (visit-all-on-failure, quiescence triad) red; soak leaks a listener | same bodies, same base order, one ladder per commit | per-commit revert |
| R5 | Guard churn breaks CI unrelated to the move | all | guard red on untouched code | guards updated in the same commit as their subject; `guard_set` run pre-push | revert pair-commit |
| R6 | Concurrent sessions/lanes collide mid-phase | all | "owned by another fleet" refusals; history-§10-style cross-lane kills | phases land whole per cluster; soaks in dedicated lanes with fresh `TEST_PORT_START`; no long-lived half-shimmed states | n/a (procedural) |
| R7 | Collection/runtime perf regression | all | standing-gate collect budget (±10% of 19.1 s) exceeded | declaration-gate cache and snapshot cache move with their tests; profile before/after per phase | revert offending commit |
| R8 | 3.9-floor breakage from modern syntax | TS-1+ | CI 3.9 lane import errors | `requires-python >=3.9` + a 3.9 CI lane added at TS-1; `from __future__ import annotations` house style | trivial syntax fix |
| R9 | Entry-point plugin double-registration with shim conftest | TS-2/5 | duplicate hook effects (double fleet boot attempt) | `pytest11` entry disabled until TS-2 soak; explicit refusal test (TS-2 error test) | remove entry point |
| R10 | Subprocess-spawned helpers (`_xrdcl_worker`, stub servers) break when their path moves | TS-5 | worker-timeout cascades in xrdcl suites | switch spawn to `python -m …` one spec per commit; both-forms test | revert spec |
| R11 | Premature generalization: core APIs designed for imaginary consumers | TS-2+ | core modules sprouting config knobs nothing uses; adapter contortions to fit core shapes | the §7.2 promotion rule — adapter by default, promote on evidence; NG6 | demote module back to adapter (rename) |
| R12 | k8s ambition bleeds scope into this plan | TS-4 | backend interface growing k8s-only members; TS-4 soak slipping | TS-9 is design-doc-gated and separately approved; §8.4 rules are the ONLY k8s work this plan performs | strip interface to LocalBackend's needs |
| R13 | Additive features creep into parity commits, making NG2 uncheckable | TS-2+ | a migration commit's diff contains new public surface (new verb, new report type, new event emitter) | the §7.3 parity/additive split per feature; additive halves land post-soak as separate gated commits with their own triads; review rule: parity diffs contain moves + shims only | drop the additive commit; parity is untouched |

---

## 14. Standing Acceptance Gate — runbook

Run per phase (and per commit for TS-2/TS-4 flagged steps), in an isolated
lane so concurrent sessions are unaffected:

```bash
LANE=/tmp/xrd-test-migration-lane PORTS=23000
cd <repo>

# 1. Guards
python3 tools/ci/check_file_size.py && python3 tools/ci/check_complexity.py
python3 tools/ci/guard_set.py            # full updated set

# 2. Collection budget (±10% of 19.1 s wall / 16.0 s user, best of 3)
time TEST_ROOT=$LANE TEST_PORT_START=$PORTS python3 -m pytest --collect-only -q | tail -2

# 3. Harness unit surface (must pass UNMODIFIED through shims)
TEST_ROOT=$LANE TEST_PORT_START=$PORTS PYTHONPATH=tests \
  python3 -m pytest tests/test_conftest_fleet_lifecycle.py \
                    tests/test_server_registry_smoke.py \
                    tests/test_fleet_prep_cache.py \
                    tests/test_fleet_teardown_orphans.py

# 4. Real-fleet round trip + conservation
TEST_ROOT=$LANE TEST_PORT_START=$PORTS PYTHONPATH=tests \
  python3 -m pytest tests/test_cache_write_through.py
(cd tests && TEST_ROOT=$LANE TEST_PORT_START=$PORTS \
  python3 -m cmdscripts.manage_test_servers start-all && \
  python3 -m cmdscripts.manage_test_servers status && \
  python3 -m cmdscripts.manage_test_servers stop-all)

# 5. xdist smoke
TEST_ROOT=$LANE TEST_PORT_START=$PORTS PYTHONPATH=tests \
  python3 -m pytest tests/test_cache_write_through.py -n 2

# 6. Leak check -- ownership-based.  NEVER a port window, never bare pgrep.
#    `find_orphans` is the suite's own ownership rule: TEST_ROOT matched as a
#    WHOLE PATH, parent-argv inheritance so nginx workers are found through
#    their master, and cmsd in FLEET_EXES.  Exit 1 means the lane leaked.
(cd tests && TEST_ROOT=$LANE python3 -c "
import os, sys
from brix_suite.orphans import find_orphans
root = os.environ['TEST_ROOT']
orphans = find_orphans(root)
print('%d orphan fleet process(es) rooted at %s' % (len(orphans), root))
sys.exit(1 if orphans else 0)")
```

**Two ways step 6 was measured to lie, both fixed above.** A *port-window*
scan misses everything a lane binds outside the window: mesh components take
ports from their own `cms-mesh/`/`hybrid-mesh/` cfg files rather than from the
ladder, and one measured lane held 39 listeners spanning 15004..46133 -- a
31130-port spread, wider than the complete 18480-port lane, so no window
anchored at the lane base could have contained them. The window this plan
shipped with was `$PORTS..$PORTS+1000`: 1000 ports, under half the 2096-port
named ledger and 5% of the lane. It printed nothing while 108 processes were
up. And `pgrep -af "$LANE" | wc -l` counts the *invoking shell*, whose own
command line contains the lane string: a lane that never existed reports 1, so
"1 surviving process" reads as a clean result and a genuine single survivor
reads as 2.
Both were live in the recipe this plan shipped with; `find_orphans` has neither
failure mode, and it is the same code the teardown reaper trusts.

**Choosing `PORTS` -- a lane is 18480 ports wide, not 178.** `port_ladder`
derives three nested spans from one base: the 176 named `*_PORT` constants land
densely in `base+1..base+178`, the *reserved* named ledger runs on to
`base+2096` as growth headroom, and `ephemeral_port.free_port` draws mock
listener and differential-upstream ports from `base+2097..base+18480`. Only the
first span is visible in `ss` output, which is why two lanes a few hundred
apart appear to coexist happily -- their bound sets miss each other while their
mock pools overlap almost entirely, so the collision arrives later and
nondeterministically, out of a `free_port` draw rather than out of boot. Space
concurrent lanes by **>= 18480**. `port_ladder.py:479` refuses a base above
47055 outright, so one host holds at most three non-overlapping lanes -- bases
1023, 19503 and 37983 tile the space exactly.

**Corrected 2026-08-18: that tiling is wrong, because it tiles ports the
kernel has already spoken for.** `ip_local_port_range` is 32768..60999 by
default, and those are the ports the kernel hands to *outbound* sockets. The
third tile (37983) lies entirely inside it; the second tile's mock pool crosses
into it at 32768. A lane placed there fails `bind()` with EADDRINUSE on a host
where `ss` shows the port free -- measured, when the TS-3 real-fleet proof
derived a lane at 47029 and lost the race to a connection the suite itself had
open. Space concurrent lanes by >= `TOTAL_PORT_COUNT` **and** keep them clear
of `ip_local_port_range`; on a default Linux host that leaves room for exactly
**one** full lane below the ephemeral floor (1024..32767 holds 31743 ports
against a lane's 18505). A second lane can only be a partial one -- the named
ledger is `PORT_COUNT` wide (2121) and is the span servers actually bind, so
two named ledgers fit in the 4261 ports between a default lane's end (28505)
and the ephemeral floor. Read the range rather than assuming it; it is tunable
per host. `tests/test_ci_ts3_settings_live_lane.py` derives its base this way
and is the worked example.

TS-4 additionally: the 3× boot/stop soak (§11 TS-4). Timing numbers are
recorded per phase in Appendix E on landing.

---

## 15. Open Questions (resolve at the phase that needs them)

| Q | Needed by | Recommendation |
|---|---|---|
| Final spellings: `brixtest` import name; adapter keeps `brix_suite` vs renames | TS-1 | `brixtest` + `brix_suite`; settle against `check_brix_namespace.py` |
| Adapter in same wheel forever, or split distribution later | TS-8 | same wheel now (one version, one install); split only if a second consumer appears |
| Kind/starter registration mechanism: explicit `register()` call vs entry-point group | TS-4 | explicit call from adapter activation (simpler, testable); entry points only if third-party kinds materialize |
| `pytest.ini` location long-term | TS-7 | keep root `pytest.ini` while tests live in `tests/` (rootdir semantics, xdist, the `testpaths` fix); revisit only at TS-7 |
| `fleet_ports_shared_phase5.py` (1,120 LOC) consolidation design | TS-3/4 | own mini-design doc; candidate split: ladder math (core) vs shared-wave tables (adapter) |
| `cmdscripts` double-life duration | TS-5+ | keep `python -m` form indefinitely (cheap forwarder); revisit if it ever blocks |
| Asset physical move | TS-6 | decide per asset class on churn evidence, not aesthetics |
| Build backend: hatchling vs setuptools | TS-1 | hatchling (src-layout native, multi-package wheels, no legacy config); zero runtime impact |
| Where `utils/make_proxy.py`/`make_token.py` belong | TS-5 | stay in repo `utils/` (shared with non-suite tooling); wrapped by `brix_suite.security.proxy` |
| K8sBackend MVP: client access path (in-cluster runner pod vs NodePort vs port-forward), image strategy per kind, first spec subset | TS-9 design doc | in-cluster runner pod (closest to remote-suite prior art); `proc` stubs + one nginx role first |
| F15 event-schema v0 field set and stabilization point | TS-4 (skeleton) / TS-8 (v1) | start minimal — `ts, kind, spec, lane, data` — and mark the schema explicitly unstable until TS-8; credential material only ever as digests |
| Strict-template whitelist: which of the 541 templates carry deliberate literal `{}` braces (F13 addition) | TS-6 | inventory during the manifest build; strict mode stays default-off until the whitelist is complete |

**Decision note (TS-0, 2026-08-17).** The questions gating TS-1 are
settled: spellings are **`brixtest` + `brix_suite`** (already settled
de facto by the ground-up build and `check_brix_namespace.py`);
`pytest.ini` **stays at the repo root** while tests live in `tests/`
(rootdir semantics, xdist, the `testpaths` fix) — the additive
`BriXTest/pytest.ini` scopes only the BriXTest suite and does not
compete. One reconciliation the original phase text predates: the
ground-up build already created the **generic** implementations at
Appendix A's "(core)" target paths (`brixtest.fleet.registry`,
`brixtest.harness.*`, …). Verbatim moves of grown suite code cannot
land there without either clobbering the generic core or changing
suite behavior — both forbidden (NG2, §7.2). Therefore: **grown
bodies move verbatim into `brix_suite.*` (adapter) only**; the flat
name keeps working via the §10.2 shim; a "(core)" row in Appendix A
is satisfied by the already-built generic mechanism, and *adopting*
it from the legacy suite (swapping grown bodies for core calls) is
behavior change, deferred to TS-7-class tranches with their own
gates. The surface inventory is live:
`docs/refactor/testsuite-surface-inventory.md` + `.json`
(`tools/ci/dump_suite_surface.py`, idempotence-checked via
`--check`; triad in `tests/test_ci_suite_surface.py`) — 248 infra
modules measured (88 flat + 160 package submodules), 258 `settings`
constants, 899 `settings` importers, 346 `server_registry`
importers, 46 exec-shard modules with shard-implicit names.

**Decision note (TS-2, 2026-08-17).** TS-2 landed as a
**partition**, not the full plugin extraction the phase text
sketches. What moved into real modules: `conftest_part4.py`
(the sentinel arbiter, deleted after absorption), the two per-test
sentinel hooks and `_check_server_reachable`, the kill tracer, and
part5's fixture tail — now `brix_suite.harness.{kill_tracer,
sentinel,fixtures}` — plus `conftest_mu.py` →
`brix_suite.harness_ext` behind a §10.2 self-replacement shim.
`conftest.py` re-exports every moved name, so exec'd shards and
pytest's conftest-namespace collection both keep resolving them.
What deliberately did NOT move: parts 2/3 and part5's session hooks
stay exec-composed, because the pinning suite
(`tests/test_conftest_fleet_lifecycle.py`) executes `conftest.py`
**by path** as a duplicate module and depends on two properties of
that arrangement at once: *patch-transparency* (stubbing a bare
name in the one shared namespace is seen by every caller — only
true while callers and callees share conftest's global dict) and
*duplicate isolation* (plain-assignment stubs that are never
restored must not leak into live state). Absorbing those call
graphs would break one property or the other, and NG1 forbids
touching the pinning suite before TS-7 — so `pytest_configure`,
marker registration, `pytest_plugins` activation and a real
`plugin.py` are deferred behind the pinning suite's TS-7
retirement. Two sanctioned deltas from verbatim: the tracer now
installs at **first import** (a by-path re-execution of conftest.py
can no longer stack a second `os.kill`/`Popen` wrapper — the
pre-TS-2 double-wrap; pinned by the TS-2 triad), and the moved
`registry` fixture anchors its tests-dir on `settings.__file__`
instead of the moving module's `__file__`. Guard fallout: file-size
and complexity ratchets now scan `BriXTest/src` (no grandfathered
backlog), and guard #8 (`check_import_direction.py`) landed early —
§12 slated it for TS-8 — wired into `guards.yml`. Surface inventory
regenerated: 247 modules (part4 gone; `conftest_mu` now a 13-line
alias shim).

**Decision note (TS-3, 2026-08-18).** The 580-line grown `settings`
body moved **verbatim** (sha256-pinned) to
`brix_suite.settings_values`, with a second verbatim archive at
`brix_suite/_legacy/settings_flat.py` as the phase's rollback anchor;
`brix_suite.settings` is a thin facade that adds `TESTS_DIR` and the
typed `SETTINGS` object, and `tests/settings.py` is now a §10.2
self-replacement shim. Body and facade are two files only because the
600-line ratchet and the verbatim rule cannot both be satisfied in
one. **Why self-replacement rather than `install_legacy_module`:** the
alias helper needs a caller to have installed it first, and the
suite's standalone entry points — `cmdscripts`, the `tools/ci` guards,
ad-hoc `python -c` — import `settings` with no prior caller, no
conftest and no `PYTHONPATH`. The shim bootstraps `brixtest/src`
itself, and `sys.modules[__name__] = <canonical>` makes the flat and
dotted names **one module object**: a test that monkeypatches
`settings.X` is seen by `brix_suite.settings.X` and the reverse, which
neither a copy nor a proxy would give, and the import-time side
effects (TEST_ROOT republish, TMPDIR pin, ladder rebase + env
republish) still fire exactly once whichever name is imported first.

`SuiteSettings` is a frozen dataclass whose `from_env()` is the only
environment read and whose `derive()` recomputes lane-dependent
defaults unless a value was set explicitly (C2 precedence);
`PortLedger` gained `aliases` (`XRDHTTP_HTTPS_PORT` shares
`XRDHTTP_HTTP_PORT`'s socket and is excluded from duplicate detection)
and attribute access, per §9.2.1's one-named-attribute-per-constant
rule. The **ladder**, not the historical literal defaults, is the
runtime source of truth: `_ladder_ledger` builds from
`port_ladder.rebase_settings`, and the object simply reports what the
lane really bound.

Rule 6 (validation warn-only for one full phase) forced one design
change worth recording: the core ledger's 1024 floor would have turned
`TEST_PORT_START=80` into a *construction-time* refusal, where today
such a lane imports fine and only fails when a server tries to bind.
`_ladder_ledger` therefore returns `None` below 1024 and
`_warn_lane_sanity` logs — the phase that introduces the object adds
no refusal that did not already fire.

Two latent breakages the move would otherwise have shipped were caught
before landing. The moved `registry` fixture anchored the tests
directory on `settings.__file__`, which after the move resolves
*inside the package* — it now uses `settings.TESTS_DIR`. And
`check_ports_doc.py` regex-scraped `tests/settings.py`, which is now
an empty shim: it would have found zero constants and passed
vacuously, forever. It reads `SETTINGS.ports.iter_named_ports()`
instead, with a 150-name floor so a guard that stops seeing the ledger
**fails** rather than silently agreeing.

Guard #3 landed: `tools/ci/check_shim_completeness.py` plus the
append-only `docs/refactor/testsuite-shim-baseline.json`, which freezes
the 260 names `settings` exported while still a flat file. The
baseline was frozen from the *pre-shim* inventory before
`dump_suite_surface.py` learned to follow shims, so it records the flat
file's surface rather than the shim's own (empty) one; the dumper now
AST-detects `sys.modules[__name__] = X` and takes the surface by
subprocess runtime introspection of the canonical module, which stays
correct however many files that body is later split across. The
foreign-lane refusal moved to `brixtest.config.lanes.refuse_foreign_lane()`
with `conftest.py` calling it, so the message has exactly one source;
the triad pins it byte-identical down to "The foreign listener was not
modified."

Two reconciliations with work that landed outside this phase. The tree
was renamed `BriXTest/` → `brixtest/` mid-phase; the guards already
read `brixtest/src`, and the two workflow steps still installing
`-e BriXTest/` (coverage, asan) are corrected here. The repo-root
`brixtest/` project directory does **not** shadow the packaged
`brixtest/src/brixtest`: PEP 420 records an `__init__.py`-less
directory only as a namespace portion and continues the path scan, so
the regular package wins even when `brixtest/src` is appended last —
verified, and pinned by a triad test that also asserts no
`brixtest/__init__.py` exists to flip that precedence.

One trap this phase paid for twice, worth stating once. A directory
rename that preserves mtimes leaves every `__pycache__` entry *valid*
— the size/mtime check still matches — while the cached code object's
`co_filename` still names the **old** tree. Anything that derives a
path from `__file__` or `co_filename` then resolves into a directory
that no longer exists, and the error names a plausible relative path
rather than the rename. It surfaced as a BriXTest self-test failing on
`config='../configs/servers/echo.json.in'` whose case definition
recorded `BriXTest/selftests/…` — 114 stale `.pyc` under the renamed
tree and 13 more under the moved `brix_suite` package. Clearing them
made the suite green with no code change. The `settings.TESTS_DIR`
anchor above is the same hazard caught statically; after any move or
rename in this migration, drop the bytecode caches before believing a
failure.

Deferred, deliberately. The `fleet_ports_shared_phase5.py` /
`port_ladder.py` consolidation keeps its own mini-design (§15 row):
the shared lifecycle ladder took another intentional width bump
(799 → 803) *during* this phase, which is precisely the live churn
that argues against folding it into the settings object yet.
Constructing `SuiteSettings` at `pytest_configure` time stays deferred
behind the TS-2 partition, for the same pinning-suite reasons.

**Follow-up note (TS-3 real-fleet proof, 2026-08-18).** The Appendix E row
below recorded a real-fleet round trip for this phase, and nothing in the
tree re-ran it: the claim had decayed into prose, and the 20 tests in
`test_ci_ts3_settings_object.py` are hermetic by construction — every one
of them is arithmetic over an environment dict, which is the right shape
for the ladder maths and structurally unable to answer whether a *server*
started under the rebased ladder binds where `SETTINGS` says it does.
`tests/test_ci_ts3_settings_live_lane.py` is that round trip, committed:
13 tests, ~8 s, one real `main` nginx booted in a lane of its own through
the same three calls `manage_test_servers start-all` makes (prepare,
`launcher.start`, publish manifest + ready marker), restricted to one spec.
It asserts the four things no hermetic test reaches — the kernel's bound
set agrees with `SETTINGS.ports`; the import-time side effects fired in a
child that imported settings for the first time in a foreign lane; the
conftest lane gate driven by a live socket rather than a monkeypatched
flag (own-and-complete attaches without touching the tree, foreign refuses
and leaves the listener running, and `TEST_SKIP_SERVER_SETUP=1` does not
buy a way past the refusal); and ownership-based leak accounting over
processes that really exist.

It cost two findings before it was green, both of which invalidate advice
this plan gives elsewhere.

**A lane must clear the kernel, not only the other lanes.** §14 step 6
derives lane bases by tiling 1024..65535 into `TOTAL_PORT_COUNT`-wide
slots and names 1023 / 19503 / 37983 as the three that fit. Deriving the
proof lane that way produced base 47029, and `bind()` failed EADDRINUSE on
a host where `ss` showed the port free: `ip_local_port_range` is
32768..60999, so the tile sat inside the range the kernel hands to
*outbound* sockets and a connection this very suite had open owned it.
The same defect is in the documented tiling — the third tile is entirely
inside the ephemeral range, and the second tile's mock pool crosses into
it at 32768 — which means a "correctly spaced" second or third lane still
collides, nondeterministically, out of a `bind()` rather than out of a
`free_port` draw. Only ONE full lane fits below the ephemeral floor on a
default Linux host. The live-lane file therefore reads the range from
`/proc/sys/net/ipv4/ip_local_port_range` at import and takes the highest
base whose complete *named* ledger (`PORT_COUNT` wide — the span servers
actually bind) still clears the floor. Whether `ephemeral_port.free_port`
should exclude the range as well is a real question for the deferred ports
consolidation; today it can draw straight into it.

**`serial` does not keep a module on one worker.** The file's first
`--dist=loadgroup` run split its 13 tests across gw0 and gw1, `serial`
marker and all, and the two module fixtures booted the same lane at once:
one wiped `pki/` while the other generated into it, and the boot failed on
a half-generated CA with no warning from either side — the artifact
sentinels are checked when a snapshot is *stored*, not after generation,
so an incomplete tree passes through silently. The cause is scheduling,
not the marker: `pytest.mark.xdist_group("serial")` is added in
`pytest_collection_modifyitems`, which each *worker* runs, while the
controller's loadgroup scheduler keys on the `@group` suffix in the
nodeid. conftest already appends that suffix by hand for the two families
that hit this (`cvmfs-fixed-ports`, `ci-guards`); `serial` never got the
treatment, so **every `serial`-marked module in the suite can currently be
split**. The fix that belongs in conftest is off-limits until TS-7, so the
live-lane file holds the lane under an exclusive `flock` for the life of
its fixture and a test asserts, from a child process, that a second owner
is refused. Making `serial` authoritative is TS-7 work and is listed
there.

**Decision note (TS-4 item 1, 2026-08-18).** `server_registry.py` moved to
`brix_suite/registry.py` (383 LOC, one file — under the 600 cap, so no
body/facade split; a split would have been actively wrong here, because
`from body import *` copies the `_SPECS` binding and the whole point of
the §10.2 shim is that there is exactly ONE dict). The flat name is now a
self-replacement shim; 354 dependent modules and 879 `NginxInstanceSpec`
spellings were untouched.

Three deviations from a byte-identical move, each forced rather than
chosen, and each pinned:

1. The `settings` import takes its canonical spelling
   (`from brix_suite.settings import …`). Equivalent at runtime — the two
   names are one module — but it does not assume the flat `tests/` tree is
   on `sys.path`.
2. `InstanceSpec` becomes the class name, with `NginxInstanceSpec` kept as
   a plain alias, not a subclass. A subclass would give the two spellings
   two `__eq__` and two field sets; the alias keeps `type(a) is type(b)`.
   The name had been wrong for a long time: the same dataclass already
   carries `kind` values `xrootd`, `xrdhttp`, `haproxy`, `proc` and
   `external`.
3. `_caller_site()` identified this module by the basename
   `server_registry.py`. That check does not fail after the move — it
   *lies*: the `f_back` walk stops on the registry's own frame, so every
   duplicate-registration error would name the registry instead of the
   test that clashed. Rewritten against `os.path.abspath(__file__)`. This
   is the same class of defect as TS-3's `TESTS_DIR` hop count: a
   path-derived constant that silently starts naming the wrong thing, with
   no exception to point at it. Both were found only by moving a file, so
   assume the rest of the migration hides more; the general rule is that
   anything deriving a path from `__file__`, `co_filename` or a hard-coded
   basename is a move hazard and must be re-derived, not carried.

The existing `test_server_registry_smoke.py` already pinned (3): it
asserts the duplicate-registration message names
`test_server_registry_smoke.py`. It stayed green unmodified — which is
the whole argument for the pinning suite, since nothing in the TS-4 plan
predicted that failure.

**Decision note (TS-4 items 2 and 3, 2026-08-18).** The three nginx helpers
(`_nginx_bin`, `_inject_nginx_load_modules`, `_inject_nginx_runtime_paths`)
existed in four copies — `server_launcher.py` and all three
`_server_launcher_part2_mixin{a,b,c}.py` — because the shard split
duplicated them rather than importing them. They are one function each in
`brix_suite/nginx_tools.py` now, re-exported from all four old homes with
`# noqa: F401` so nothing importing them by their old path changed. The
`live_common` imports inside those helpers stayed function-local: hoisting
them would have created an import cycle and, worse, would have made them
un-monkeypatchable by the tests that fake the binary.

`brix_suite/kinds.py` supplies the six `KindProfile` rows the core
`brixtest.fleet.kinds` mechanism ships without. Two of them carry a
*callable* stop strategy rather than a named one — `nginx_quit` (nginx
speaks `-s quit`, not a signal) and `external_stop` (the spec's own
`stop_argv`). Writing those callables is what forced
`LocalBackend._pidfile_pid` and `._term_then_kill` to become public
`pidfile_pid` / `term_then_kill`: the backend's docstring advertises
callable strategies to adapters, and an adapter that must reach through a
leading underscore to reuse the SIGTERM→SIGKILL escalation will instead
reimplement it, badly, and diverge on the timeout.

`LauncherKind` wraps each profile with the two facts the launcher ladders
branch on today — which `RegistryLauncher` start method applies (`None`
means the nginx render path) and how quiescence is decided
(`pidfile` / `ports-only` / `never`). The rows are *not wired in yet*.
`test_ci_ts4_kinds_and_nginx_tools.py` first pins that each row describes
what the four existing `if spec.kind ==` ladders already do, in both the
nothing-running and pidfile-on-disk states. That ordering is deliberate:
item 5 flips one ladder per commit onto these rows, and each flip is then
a refactor with a test that was green before it and must stay green
after, rather than a rewrite with a new test written to match it.

**Decision note (TS-4 item 7, 2026-08-18).** `fleet_specs.py` (405) +
`fleet_specs_part2.py` (340) + `fleet_values.py` (131) merged into
`brix_suite/catalogue/`. 876 lines is well past the 600 line, so this is
the phase's first *package* rather than a single module: seven topic
modules (`_shared`, `core`, `backends`, `support`, `ha`, `dedicated`,
`values`), largest 258 lines, with `__init__.py` re-exporting every name
the three flat modules exported. Splitting by topic rather than by
line-count keeps the seams where a reader would draw them anyway, and the
per-module import lists were derived mechanically — an AST free-variable
pass over each block — rather than by eye, so no block silently kept
relying on a name it never imported.

Which is exactly the defect this item existed to fix. `fleet_specs_part2.py`
was never a module: `fleet_specs.py` ended by `exec`-ing it into its own
globals via `split_continuation.load`, so its functions closed over `_data`,
`_ded` and `_CRL_DIR` without importing them. `import fleet_specs_part2`
raised `NameError: name '_data' is not defined` from `ha_specs()` — the
breakage measured in §2.3. Both flat names are now §10.2 shims onto the one
package, so that import works for the first time; the pin is
`test_the_shard_imports_on_its_own_now`.

The move is verbatim, and *machine-checked* to be. The three pre-move
bodies are archived byte-for-byte under `brix_suite/_legacy/*_flat.py`
(the `settings_flat.py` precedent from TS-3), and
`test_the_move_was_verbatim_apart_from_two_named_deviations` parses both
trees and asserts that the set of definitions whose source text changed is
*exactly* the two we own — it fails both on an unannounced change and on a
declared deviation that stopped deviating. 17 of 19 definitions are
byte-identical.

The two deviations:

1. `_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))` would name the
   catalogue package after the move, not the flat `tests/` tree the fleet
   renders configs out of. Imported from `brix_suite.settings` instead.
   This is the **third** instance of the move-hazard class named in the
   item 1 note (after TS-3's `TESTS_DIR` hop count and `_caller_site`'s
   basename check) and the second where the wrong answer would have been
   silent. Treat the rule as load-bearing for the rest of the migration:
   grep each block for `__file__` *before* moving it.
2. `register_full_fleet` imports `_SPECS` from `brix_suite.registry` rather
   than through the `server_registry` shim — the catalogue must import
   without the flat `tests/` tree on `sys.path`.

Guard #3's baselines for all three modules were frozen **before** the
shims went in, from the pre-move inventory — the same freeze-before-shim
ordering used for `server_registry`. Freezing afterwards would have
recorded whatever the shim happened to expose and pinned nothing.

**Decision note (TS-4 item 4, 2026-08-18) — built, pinned, and deliberately
not installed.** The six flat `server_launcher*` modules are now also a real
package, `tests/brix_suite/launcher/`: `errors` (28) + `start` (450) +
`control` (386) + `internals` (369) + `harness` (168) + an `__init__` that
composes `RegistryLauncher` from the three topic classes with ordinary
imports instead of the `exec` chain. 69 method bodies moved byte-for-byte;
the slice-letter names (`_RegistryLauncherMixinA/B/C`) survive as aliases,
not subclasses, so the MRO is the same object graph either way. Item 4's
second half is done too: `LocalBackend` is measured against the §8.1 seam
by `brixtest.testing.check_backend_contract`, which shipped with the core
and until now **had no caller anywhere in the tree** — the seam was
declared conformant and never tested.

The package is nonetheless **not wired in**: `server_launcher.py` is still
the live module and no §10.2 shim points at the package. That is a measured
decision, and `test_ci_ts4_launcher_and_deploy.py` ends with the
measurement.

The pinning suite rebinds names *in the launcher's module dict* —
`monkeypatch.setattr("server_launcher.Path", ...)` at
`test_server_registry_smoke.py:210`, and
`...("server_launcher.REGISTRY_STRICT_TEMPLATES", True)` at smoke:402 and
`test_fleet_port_uniqueness.py:165`. Those work only while every method of
the class reads its globals out of **one shared dict**, which is exactly
what the `exec` composition gives it. Split into real modules, a rebind on
the package namespace is invisible to the topic module that runs the code,
and *nothing raises*: the patch silently does nothing and the test silently
asserts against unpatched behaviour. Module-*object* patches
(`subprocess.run`, `socket.create_connection`) do carry, because those are
shared objects rather than dict entries — which is what makes the failure
selective enough to miss. This is the same patch-transparency property that
kept `conftest.py` parts 2/3/5 exec-composed at TS-2. NG1 forbids editing
either pinning file before TS-7, so the package waits for TS-7, which flips
it on and deletes the last test in that file.

The constructor rewrite is the **fourth** instance of the move-hazard class
(after TS-3's hop count, `_caller_site`'s basename check, and the
catalogue's `_TESTS_DIR`): `RegistryLauncher.__init__` defaulted
`self.tests_dir` to `os.path.dirname(__file__)`, which after the move
resolves to `brix_suite/launcher` — a directory that exists, so nothing
would raise. It is **latent** rather than live, because grep proves nothing
reads `self.tests_dir` today. Fixed anyway: the next caller to read it
would have had no way to notice.

One consequence worth recording. The package's verbatim check compares
against the **live flat modules**, not the frozen `_legacy` archives. Item 5
below flipped four ladders in the flat mixins *after* this package was
built; pointing the comparison at the archives would have let that
divergence sit unnoticed until TS-7 installed a launcher missing them. The
archives keep their own, narrower test: that nothing imports them.

**Decision note (TS-4 item 5, 2026-08-18) — four kind ladders onto the
rows.** `RegistryLauncher` answered four questions about the same six kinds
with four hand-written `if spec.kind == ...` chains: which method starts it
(`start`, mixina), whether `stop()` can be skipped outright (`_quiescent`,
mixina), whether `stop()` reaps from disk or from memory (`stop`, mixinb),
and how the from-disk reap works (`_stop_from_disk`, mixinc). All four now
read `brix_suite.kinds.LAUNCHER_KINDS`. No `spec.kind` comparison remains
in any of the three mixins, and a test asserts that — the literals *are* the
ladder, so their return is the drift.

Every ladder had an `else` that quietly did the nginx thing, and the flip
keeps it: the bodies use `LAUNCHER_KINDS.get(...)`, not `launcher_kind()`,
which raises. An unregistered kind is a spec bug for the registry's own
validation to catch, not a crash in the middle of a fleet teardown.

`_stop_from_disk` needed one new fact in the table rather than a straight
deletion. haproxy TERMs its pidfile and returns; xrootd and xrdhttp TERM,
wait five seconds for the master to go, then KILL. Unifying them would have
been a behaviour change, and item 5 is a refactor — so the difference moved
into the row as `kill_grace` (0.0 for haproxy, 5.0 for the xrootd pair)
instead of being flattened. The row now carries `pidfile`, `start_method`,
`quiescence`, and `kill_grace`, which is the whole of what the four ladders
encoded.

The pin is behavioural, not static, and for a specific reason: the failure
mode a flip like this introduces is a **wrong attribute name on a row**.
The first draft read `row.profile.pidfile_relpath`; the field is `pidfile`.
That imports cleanly, passes every static check, and raises only when a real
teardown runs it — which is how it surfaced, as a
`[conftest] stale-fleet preflight warning` on the next unrelated test run
rather than as a failure. `test_ci_ts4_kind_ladder_flip.py` (9 tests)
therefore executes each flipped body against real specs and real on-disk
prefixes: `endpoint_for` and `declared_ports` are pure functions of a spec,
so nothing has to touch the `_SPECS` singleton and no stray name can leak
into a later fleet boot.

**Decision note (TS-4 item 6, 2026-08-18) — prep steps, declares, orphans.**
`fleet_declares` and `fleet_orphans` moved verbatim to
`brix_suite/declares.py` and `brix_suite/orphans.py` behind §10.2 shims.
`fleet_prep` moved to `brix_suite/prep_steps.py` and did **not** move
verbatim: §9.2.4 asks for the pipeline to become `PrepStep` objects, and it
now is — `CRYPTO_STEPS` (pki, jwks-refresh-key, signing-key,
fleet-artifacts, issued-tokens) and `SESSION_STEPS` (crl-drops,
authdb-placeholder, stage-hook), structurally matching
`brixtest.fleet.prep.PrepStep` so the core engine and `prepare()` drive one
implementation of the pipeline rather than a copy each.

Three deviations from the plan text, each for a reason worth recording.

1. **The engine already existed.** §9.2.4 sketches a `FleetPrep` to be
   written; `brixtest/fleet/prep.py` has shipped one since the core work,
   with `snapshot_dir` and `ttl_seconds` as constructor knobs — the plan's
   `cache_root` and `cache_ttl` — and per-step `stamp()` in place of the
   module-level `generator_sources` tuple. Item 6 supplies it steps rather
   than a second engine.

2. **`prepare()` keeps the grown snapshot cache** instead of delegating to
   that engine. The two disagree about where a snapshot lives (path-hashed
   directory outside the lane vs. lane-rooted `snapshot_dir`) and what
   stamps it, and `test_fleet_prep_cache.py` pins the grown layout by
   reading `meta.json` and `_CACHE_TTL_SECONDS` directly. §9.2.4 already
   schedules that conversion — "the §11 unit tests convert from
   monkeypatch-heavy to constructor-parameter tests" — for the phase where
   editing the pinning suite is allowed. That is TS-7, not TS-4.

3. **The two verbatim modules landed in `brix_suite/`, not `brixtest/fleet/`,**
   which the item text names. `brixtest/fleet/declares.py` and
   `orphans.py` already exist with *different* signatures — the core's
   `analyze_source(path) -> TestUsage` against the flat
   `analyze_source(source) -> list[TestUsage]`, and an `owns(lane, pid, port)`
   against `owns(test_root, text)` — and are pinned by the example suite.
   Moving the flat bodies onto those paths would have been an overwrite, not
   a move. Adapter-side placement is the right home for both; reconciling the
   two `analyze_source` signatures is a TS-5/TS-7 question, not a TS-4 one.

The shim had to stay **flat-to-flat**, and that is the finding item 4 paid
for. `test_fleet_prep_cache.py` rebinds five names in `fleet_prep`'s module
dict — `regenerate_pki`, `_make_token`, `_run`, `_GENERATOR_SOURCES`,
`_cache_dir` — and `prepare()` reads all five out of that same dict at call
time. A package split would have put the rebind on one dict and the read on
another with nothing raising. One module object means one dict, so all five
survive; `test_ci_ts4_prep_and_declares.py` asserts the property directly
rather than trusting it, by constructing a step *before* rebinding its
generator and checking the rebind is what runs. That test exists because the
tempting "optimisation" — `self._generate = regenerate_pki` in
`PkiStep.__init__` — would make every test in `test_fleet_prep_cache.py`
run the real openssl and still pass.

`TESTS_DIR` was the **fifth** instance of the move-hazard class, and the
first that was live rather than latent: `Path(__file__).resolve().parent`
would have resolved into `tests/brix_suite` after the move, making
`UTILS_DIR` the non-existent `tests/utils` and every `_GENERATOR_SOURCES`
entry a path to nothing. Nothing raises at import — the cache would simply
have stamped five missing files and then happily restored snapshots across
generator edits it could no longer see. It now comes from
`brix_suite.settings`, and a test asserts all five sources exist.

**Finding (TS-4 phase soak, 2026-08-18) — `test_fleet_liveness` times out for
a reason that has nothing to do with crash-looping.** It is the one red test
carried across TS-0…TS-4 and it had never been shown passing, so the soak
settled what it was actually reporting. The answer is that its sampling layer
costs more than its own timeout budget, and no fleet state can change that.

`pids_on_port()` shells out to `ss -ltnp` **once per port**. The `-p` flag is
what dominates: resolving socket inodes to PIDs walks all of `/proc`, and that
walk is O(processes on the host) whether or not a `sport` filter is attached.
Measured on this host, `ss -ltnp '( sport = :N )'` takes 410 ms against 471 ms
for an unfiltered whole-host `ss -ltnp` — the filter saves 13%, so a per-port
query costs essentially what a fleet-wide survey costs.

The test performs six sweeps of the fleet: `_live_fleet_ports()`, the start
snapshot, and `END_SAMPLES` = 4 end samples. At 126 registered specs that is
756 invocations, ≈ 289 s, against a fixed 21.5 s of `SETTLE` plus gaps and a
`pytest.mark.timeout(120)` budget — ≈ 310 s of work inside a 120 s limit. The
timeout is arithmetic, not a signal. On an idle host the same sweeps cost
≈ 23 s and it passes, which is why it looks intermittent rather than broken:
it is a load-sensitive measurement defect whose threshold this repo's own
concurrent fleets sit right on top of.

The fix already exists in the same module and is already documented for this
exact case. `lib_py/util.listening_port_pids()` takes **one** `ss -ltnp` survey
and returns `port -> {pid}`, and its docstring names the caller: "a single
fleet-wide survey costs about the same as one per-port query, so callers that
would otherwise probe many ports (the ~127-port fleet teardown sweep) take this
snapshot once instead of spawning one subprocess per port." Six surveys replace
756 per-port calls, and the 120 s budget stops being marginal.

**Not fixed here, deliberately.** `test_fleet_liveness.py` is pre-existing
pinning-suite code, and NG1 holds it unmodified until TS-7; a passing test is
not worth breaking the one property that makes the whole migration auditable.
So the substance was proved *without* touching it: a scratch driver imports the
test's own pure detector — `_classify`, `SETTLE`, `END_SAMPLES`,
`END_SAMPLE_GAP` — and drives it from `listening_port_pids()` instead of
`pids_on_port()`. Same window, same assertions, same signatures; only the
sampler differs. Against a full fleet on the isolated 30500 lane it read
`registered=126 live=126` and returned **"none of 126 live servers is
crash-looping" in 27.4 s of a 120 s budget, using 5 surveys where the
per-port path would have made 756 `ss` calls.** The fleet is healthy and has
been all along; only the instrument was too expensive to say so.

The same fleet, in the same run, then failed `test_fleet_liveness.py` as
written — and *where* it failed is the confirmation. `pytest-timeout` fired at
120 s with the traceback bottoming out in `selectors.poll` beneath
`subprocess.run`: the test was blocked waiting on an `ss` child, not sitting in
its 20 s `time.sleep(SETTLE)`. The module's other four tests — the hermetic
`_classify` signature checks that take no samples at all — passed. Slow
sampler, sound detector, healthy fleet.

Two things follow for TS-7, and both are entered on its checklist:

1. Swap the sampler in `test_fleet_liveness.py` to `listening_port_pids()`.
   `_classify` needs no change — it already takes a `{pid: age}` mapping, so
   the edit is confined to `_listeners_with_age` and `_live_fleet_ports`.
2. Audit the rest of the suite for the same shape. The per-port-`ss`-in-a-loop
   pattern is cheap to write and its cost only shows up at fleet scale on a
   loaded host, which is precisely when a timeout reads as a flake and gets
   re-run rather than diagnosed.

---

## Appendix A — Module → target map (complete, 2026-08-17 inventory)

Unlabeled targets are adapter (`brix_suite.*`); **(core)** marks
promotions into `brixtest` per the §7.2 rule.

| Current (flat in `tests/`) | Target | Shim type |
|---|---|---|
| `settings.py` | `brix_suite.settings` on `brixtest.config` **(machinery core)** | legacy-module install (§10.2) |
| `port_ladder.py`, `ephemeral_port.py` | `brixtest.config.ports` / `brixtest.util.proc` **(core)** | alias |
| `fleet_ports.py`, `fleet_ports_exclusive.py`, `fleet_ports_shared_phase5.py`, `fleet_ports_shared_waves.py`, `fleet_lifecycle_ports.py` | `brix_suite.ports` (tables) + core ladder math | alias |
| `server_registry.py` | `brixtest.fleet.registry` **(core)** | **alias (stateful)** |
| `fleet_specs.py`, `fleet_specs_part2.py`, `fleet_values.py` | `brix_suite.catalogue` | alias |
| `server_launcher.py`, `server_launcher_part2.py`, `_server_launcher_part2_mixin{a,b,c}.py`, `server_launcher_part3.py`, `server_launcher_errors.py` | `brixtest.fleet.launcher`/`harness`/`errors` **(core engine)** + `brixtest.deploy.local` **(core)** + `brix_suite.kinds`/`nginx_tools` | alias |
| `fleet_prep.py` | `brixtest.fleet.prep` **(core engine)** + `brix_suite.prep_steps` | wrapper fn |
| `fleet_declares.py` | `brixtest.fleet.declares` **(core)** | alias |
| `fleet_orphans.py` | `brixtest.fleet.orphans` **(core)** | **alias (CLI-imported)** |
| `cms_parent_stubs.py`, `upstream_protocol_stubs.py` | `brix_suite.servers` peers | alias |
| `conftest.py` + parts 2–5, `conftest_mu.py`, `split_continuation.py` | `brixtest.harness.*` **(core)** + `brix_suite.harness_ext` (conftest stays as activation + re-export; `split_continuation` survives for test-side `reexport` only) | special (§11 TS-2) |
| `pki_helpers.py` | `brix_suite.security.pki` | alias |
| `lib_py/pki.py` | `brix_suite._legacy` (TS-5 finding) | alias |
| `mint_delegation_certs.py` | `cli/` cluster — a script, not a library | alias |
| `tokenforge.py` + 2 parts + 4 mixins, `token_differential.py` | `brix_suite.security.tokens`, `.tokens_vectors` | alias |
| `x509forge.py` + 2 parts, `x509_differential.py`, `x509_matrix_differential.py` | `brix_suite.security.x509`, `.x509_vectors`, `.x509_matrix_vectors` (TS-5 finding: the two differentials share a shape and nothing else — one replays named hostile scenarios against a per-credential `WlcgInstance`, the other replays the clause matrix against one `ConformanceFleet`; merging them would have produced one module with two disjoint halves and two FINDINGS paths) | alias |
| `kdc_helpers.py` | `brix_suite.security.kdc` | alias |
| `_xrdcl_proxy.py`, `_xrdcl_proxy_part2.py`, `_xrdcl_worker.py` | `brixtest.clients.procworker` **(core protocol)** + `brix_suite.clients` (XrdCl specifics) | alias + spawn-form switch |
| `guard_http_lib.py`, `cli_pty.py`, `gridftp_client_env.py` | `brix_suite.clients.http` / `brixtest.clients.pty` **(core)** / `brix_suite.clients.gridftp` | alias |
| `lib/*.py` (8 stub servers + `tokenconf.py`) | `brix_suite.servers.*` | alias + spawn-form switch |
| `cms_mesh_lib.py` + parts 2–3, `cms_mesh_servers.py` | `brix_suite.mesh.cms_mesh_lib` + parts, `.cms_mesh_servers` **(DELIVERED — names kept, see below)** | alias |
| `hybrid_mesh_lib.py`, `hybrid_mesh_servers.py` | `brix_suite.mesh.hybrid_mesh_lib`, `.hybrid_mesh_servers` **(DELIVERED)** | alias |
| `wlcg_fleet.py`, `wlcg_conformance_fleet.py`, `mesh_config.py` | `brix_suite.mesh.wlcg_fleet`, `.wlcg_conformance_fleet`, `.mesh_config` **(DELIVERED)** | alias |

The three mesh rows above planned a **rename as well as a move**
(`cms_mesh_lib` → `mesh.cms`, and so on).  The move landed; the rename did
not, deliberately.  A verbatim-move pin anchors an archive to a
destination *by name*, so renaming in the same step leaves nothing to
compare against, and the two continuation shards are loaded **by
filename** — `split_continuation.load(globals(), __file__,
"cms_mesh_lib_part2.py", …)` — so renaming them means editing a body that
the same step is asserting is unchanged.  Names are cheap to change once
the tree is settled and the archives can be re-cut against it; a move that
cannot be checked is not.  The rename is carried to TS-8, where the
package surface is tidied under ruff/mypy anyway.
| `load_test.py` + parts 2–3, `_perf_ab_helpers.py` | `brix_suite.perf.*` | alias | **(DELIVERED — names kept.)** `_perf_netem_helpers.py` is **held back to TS-7**: it is a `test_server_registry_lint.LAUNCH_BACKLOG` entry, keyed by path relative to `tests/`, and moving it registers a new direct-launcher offender at the new path, a second in its `_legacy` archive, and a stale entry at the old one — three failures fixable only inside a pre-TS-4 test file NG1 protects. |
| `official_interop_lib.py` + part2, `backend_matrix.py`, `impersonation_gridmap_helpers.py` | `brix_suite.interop.*` | alias |
| `_cachemx.py`, `_cachemx_grid.py`, `_cachemx_catalog_data.py`, `_cachemx_catalog_schema.py`, `_cache_partial_helpers.py` | `brix_suite.cachemx.*` **(DELIVERED — names kept, as for mesh)** | alias |
| `lib_py/util.py`, `config_parse.py`, `config_templates.py`, `matrix_layer.py`, `metrics_helpers.py`, `frm_helpers.py`, `tpc_parse_helpers.py` | `brixtest.util.proc/net/configtext` **(core)** / `brix_suite.util.metrics/matrix/…` | alias (split by topic) |
| `fuzz_corpus.py` | `fuzz` package peer | alias |
| `source_guards_lib.py`, `migrate_composable_root.py` | `brix_suite.guards.*` / CLI | alias |
| `run_suite_unprivileged.py`, `cmdscripts/manage_test_servers.py` | `brixtest.cli.main` **(core)** + forwarders | forwarder |
| `lib_py/dedicated.py`, legacy `lib_py/nginx.py` paths, `lib_py/refxrootd.py` (audit), `lib_py/xrdhttp.py` (audit), `lib_py/fwd_matrix.py`/`tpc_fwd.py` (audit at TS-5) | `brix_suite._legacy.*` or their topic package per audit | alias + deprecation |
| `manage_test_servers.py` (tests top-level; 24-line bash-era tombstone that raises `RuntimeError` — see §5.4) | `brix_suite._legacy` (must keep failing loudly; refresh its stale `.sh` error text in passing) | alias |

Out of scope until TS-7: all `test_*.py`, `_test_*_helpers*.py`, `unit/`,
`resilience/`, `cvmfs/`, `userns/`, `mu_authz_lib/`, `perf/` test content,
`clauses/`, `golden/`, `fixtures/` physical location, `helpers/*.c`.

---

## Appendix B — What "well configured" means here, concretely

- **Construction over import-time computation:** any object that reads
  the environment has a `from_env()` classmethod and a plain constructor;
  infra tests construct — they never `monkeypatch` module globals or
  `importlib.reload`.
- **Data over branching:** kind/stop/pidfile behavior in `KindProfile`
  rows, not `if spec.kind ==` ladders in three files.
- **One owner per lifecycle:** the harness plugin owns session state; the
  launcher owns process state; `SuiteSettings` owns configuration; the
  registry owns specs; the backend owns process mechanics; nothing else
  writes their fields.
- **One copy per helper:** `nginx_tools.py` ends the triplication of
  §2.3; the duplication guard becomes able to see what it previously
  could not.
- **Anything that must persist across sessions lives outside both
  TEST_ROOT and `tempfile.gettempdir()`** (the suite pins TMPDIR inside
  TEST_ROOT — history §11's snapshot-location lesson, now a rule).
- **Core stays generic by rule, not intention:** adapter-by-default,
  promotion on evidence, one-way import direction, guard-enforced (§7.2).
- **Existing repo rules carry over unchanged:** ≤600 LOC/file, CCN ≤15,
  helpers-not-reimplementation, 3-tests-per-change (success + error +
  security-negative) for every shim and every moved class, findings
  recorded in docs.

---

## Appendix C — Complete infra module inventory (LOC + infra-internal imports, measured 2026-08-17)

Targets are in Appendix A; this table adds per-module size and the exact
infra dependency edges (AST-scanned; "—" = imports nothing infra-side).
Shim landing order for any phase = topological order of this column.

**Configuration / ports**

| Module | LOC | Infra imports |
|---|---|---|
| `settings.py` | 580 | port_ladder |
| `port_ladder.py` | 466 | — |
| `fleet_ports_shared_phase5.py` | 1,120 | — (pure tables) |
| `fleet_ports_shared_waves.py` | 408 | — (pure tables) |
| `fleet_ports_exclusive.py` | 299 | — (pure tables) |
| `fleet_ports.py` | 346 | fleet_specs, port_ladder, settings |
| `fleet_lifecycle_ports.py` | 91 | fleet_ports_exclusive, fleet_ports_shared_phase5, fleet_ports_shared_waves, port_ladder |
| `ephemeral_port.py` | 97 | port_ladder |

**Harness**

| Module | LOC | Infra imports |
|---|---|---|
| `conftest.py` | 514 | ephemeral_port, fleet_declares, server_launcher, server_registry, settings, split_continuation |
| `conftest_part2.py` | 460 | cmdscripts, fleet_declares, fleet_orphans, fleet_prep, fleet_specs, server_launcher, server_registry, settings |
| `conftest_part3.py` | 609 | fleet_declares, server_launcher, server_registry, settings |
| `conftest_part4.py` | 536 | fleet_declares, server_launcher, server_registry, settings |
| `conftest_part5.py` | 450 | fleet_orphans, matrix_layer, server_launcher, server_registry, settings |
| `conftest_mu.py` | 112 | (mu fixtures) |
| `split_continuation.py` | 34 | — |

**Fleet**

| Module | LOC | Infra imports |
|---|---|---|
| `server_registry.py` | 383 | settings |
| `fleet_specs.py` | 405 | cms_mesh_lib, hybrid_mesh_lib, server_launcher, server_registry, settings, split_continuation |
| `fleet_specs_part2.py` | 340 | server_registry, settings (+ `_data` from part1's namespace — exec-only, §2.3) |
| `fleet_values.py` | 131 | — |
| `server_launcher.py` | 108 | cmdscripts, config_templates, fleet_lifecycle_ports, fleet_values, server_launcher_errors, server_registry, settings, split_continuation |
| `server_launcher_part2.py` | 42 | the three mixins + config_templates, fleet_lifecycle_ports, fleet_values, server_registry, settings |
| `_server_launcher_part2_mixina.py` | 467 | cmdscripts, config_templates, fleet_lifecycle_ports, fleet_values, lib_py, server_launcher_errors, server_registry, settings |
| `_server_launcher_part2_mixinb.py` | 411 | same as mixina **+ server_launcher** (the §2.3 circularity) |
| `_server_launcher_part2_mixinc.py` | 373 | same as mixina |
| `server_launcher_part3.py` | 170 | config_templates, fleet_lifecycle_ports, fleet_values, server_registry, settings |
| `server_launcher_errors.py` | 28 | — |
| `fleet_prep.py` | 322 | cmdscripts, pki_helpers |
| `fleet_declares.py` | 416 | fleet_ports, fleet_specs |
| `fleet_orphans.py` | 188 | — |
| `cms_parent_stubs.py` | 228 | settings |
| `upstream_protocol_stubs.py` | 333 | settings |
| `manage_test_servers.py` | 24 | — (tombstone, §5.4) |

**Security / crypto**

| Module | LOC | Infra imports |
|---|---|---|
| `pki_helpers.py` | 213 | settings |
| `mint_delegation_certs.py` | 118 | x509forge |
| `tokenforge.py` | 110 | split_continuation |
| `tokenforge_part2.py` | 32 | the four `_tokenforge_part2_mixin{a..d}` |
| `tokenforge_part3.py` | 358 | — |
| `_tokenforge_part2_mixina.py` | 406 | — |
| `_tokenforge_part2_mixinb.py` | 403 | — |
| `_tokenforge_part2_mixinc.py` | 410 | — |
| `_tokenforge_part2_mixind.py` | 48 | — |
| `token_differential.py` | 135 | lib, settings, tokenforge |
| `x509forge.py` | 446 | split_continuation |
| `x509forge_part2.py` | 417 | — |
| `x509forge_part3.py` | 289 | — |
| `x509_differential.py` | 217 | ephemeral_port, settings, wlcg_fleet, x509forge |
| `x509_matrix_differential.py` | 181 | ephemeral_port, settings, wlcg_conformance_fleet, x509forge |
| `kdc_helpers.py` | 367 | settings |

**Clients**

| Module | LOC | Infra imports |
|---|---|---|
| `_xrdcl_proxy.py` | 392 | split_continuation |
| `_xrdcl_proxy_part2.py` | 188 | — |
| `_xrdcl_worker.py` | 400 | — (spawned by path — R10) |
| `guard_http_lib.py` | 128 | settings |
| `cli_pty.py` | 166 | — |
| `gridftp_client_env.py` | 33 | — |

**Mesh / interop / perf / cachemx**

| Module | LOC | Infra imports |
|---|---|---|
| `cms_mesh_lib.py` | 447 | mesh_config, port_ladder, server_launcher, settings, split_continuation |
| `cms_mesh_lib_part2.py` | 391 | mesh_config, server_launcher, settings |
| `cms_mesh_lib_part3.py` | 177 | mesh_config, server_launcher, settings |
| `cms_mesh_servers.py` | 63 | cms_mesh_lib |
| `hybrid_mesh_lib.py` | 386 | cms_mesh_lib, mesh_config, port_ladder, settings |
| `hybrid_mesh_servers.py` | 52 | hybrid_mesh_lib |
| `wlcg_fleet.py` | 159 | server_launcher, server_registry, settings |
| `wlcg_conformance_fleet.py` | 89 | server_launcher, server_registry, settings, wlcg_fleet, x509forge |
| `mesh_config.py` | 24 | — |
| `official_interop_lib.py` | 476 | port_ladder, settings, split_continuation |
| `official_interop_lib_part2.py` | 438 | server_launcher, server_registry, settings |
| `backend_matrix.py` | 60 | settings |
| `impersonation_gridmap_helpers.py` | 233 | — |
| `load_test.py` | 488 | settings, split_continuation |
| `load_test_part2.py` | 402 | settings |
| `load_test_part3.py` | 206 | settings |
| `_perf_ab_helpers.py` | 211 | — |
| `_perf_netem_helpers.py` | 480 | _perf_ab_helpers |
| `_cachemx.py` | 473 | metrics_helpers, server_launcher, server_registry, settings |
| `_cachemx_grid.py` | 108 | _cachemx |
| `_cachemx_catalog_data.py` | 416 | — |
| `_cachemx_catalog_schema.py` | 244 | — |
| `_cache_partial_helpers.py` | 410 | server_registry, settings |

**Util / guards / CLI / fuzz**

| Module | LOC | Infra imports |
|---|---|---|
| `config_parse.py` | 49 | cmdscripts, config_templates, settings |
| `config_templates.py` | 34 | — |
| `matrix_layer.py` | 398 | server_registry, settings |
| `metrics_helpers.py` | 111 | settings |
| `frm_helpers.py` | 37 | — |
| `tpc_parse_helpers.py` | 94 | — |
| `source_guards_lib.py` | 388 | — |
| `migrate_composable_root.py` | 118 | — |
| `run_suite_unprivileged.py` | 295 | fleet_orphans |
| `fuzz_corpus.py` | 488 | — |

**Subpackages**

| Module | LOC | Notes |
|---|---|---|
| `lib_py/util.py` | 201 | the process/port toolkit (§5.5) |
| `lib_py/pki.py` | 96 | a *different* `regenerate_pki` (out-of-process, mints proxies) + `DEFAULTS` + `substitute_config` — TS-5 measured it: `_legacy`, not a merge |
| `lib_py/nginx.py` | 88 | part bash-era |
| `lib_py/fwd_matrix.py` | 84 | TS-5 audit |
| `lib_py/refxrootd.py` | 81 | TS-5 audit |
| `lib_py/dedicated.py` | 73 | `_legacy` (§2.6) |
| `lib_py/xrdhttp.py` | 68 | TS-5 audit |
| `lib_py/tpc_fwd.py` | 31 | TS-5 audit |
| `lib/tokenconf.py` | 476 | → `servers/` |
| `lib/ocsp_responder.py` | 209 | → `servers/` |
| `lib/fwd_mint_proxy.py` | 180 | → `servers/` |
| `lib/mirror_shadow_server.py` | 134 | → `servers/` |
| `lib/guard_stub_server.py` | 96 | → `servers/` |
| `lib/introspect_idp_server.py` | 52 | → `servers/` |
| `lib/static_origin_server.py` | 47 | → `servers/` |
| `lib/fwd_oidc_server.py` | 43 | → `servers/` |
| `cmdscripts/` | 144 files | `manage_test_servers.py` + 143 live-scenario scripts; by name family: cvmfs 21 · cache 14 · credential 7 · user 5 · operator 5 · fwd 4 · frm 4 · tier/s3/fake/client 3 each · long tail of singletons |

---

## Appendix D — Fixed-port families (the future `PortLedger`, measured 2026-08-17)

Every constant follows the pattern
`NAME_PORT = int(os.environ.get("TEST_NAME_PORT", "<default>"))`; 178
constants total (AST-counted); `check_ports_doc.py` requires each **name** to appear in
`docs/10-reference/test-fleet-ports.md` (the authoritative per-port
narrative — not duplicated here). Families by default value:

| Family | Constants | Default range |
|---|---|---|
| Core anon/GSI/token/ref | `NGINX_ANON`, `NGINX_GSI`, `NGINX_GSI_TLS`, `NGINX_TOKEN`, `REF_BRIX`, `REF_BRIX_GSI`(+`_SHARED`), `NGINX_TOKEN_STRICT` | 11094–11099, 11119 |
| Manager/readonly/VO/CRL | `MANAGER`, `READONLY`, `VO`, `CRL`, `WEBDAV_CRL`, `CRL_DIR`, `WEBDAV_DIR`, `CRL_RELOAD`(+`_HTTP`) | 11101–11109 |
| Root-TPC / XrdHttp / authdb / krb5 | `ROOT_TPC_NGINX`, `ROOT_TPC_REF`, `XRDHTTP_ROOT`, `XRDHTTP_HTTP`, `AUTHDB`, `NGINX_KRB5`, `KRB5_KDC` | 11110–11117 |
| Conventional-looking services | `NGINX_METRICS` 9100 · `NGINX_WEBDAV` 8443 · `NGINX_HTTP_WEBDAV` 8080 · `NGINX_S3` 9001 · `NGINX_S3_TOKEN` 9002 | — |
| WebDAV TPC matrix | 7 constants (`WEBDAV_TPC_SOURCE_{REQUIRED,OPEN}`, `_DEST_{CAFILE,CADIR,NO_SERVICE_CERT,DISABLED,READONLY}`) | settings.py:221–240 |
| Upstream fault matrix | 16 constants (`UPSTREAM_{REDIRECT,WAIT,WAITRESP,ERROR,AUTH,AUTH_NOFILE,GOTORLS_NOTLS}_{NGINX,BACKEND}`) | settings.py:243–284 |
| TPC SSRF / egress guard | `TPC_SSRF_{DEFAULT,ALLOW_LOCAL,DENY_PRIVATE}`, `TPC_SRC_GUARD`, `WEBDAV_TPC_SRC_GUARD` | 11180–11182, 11218+ |
| S3 presigned / security level / proxy / bridges | `S3_PRESIGNED`(+`_STS`), `SECURITY_LEVEL_{STANDARD,PEDANTIC}`, `PROXY_NGINX`/`PROXY_UPSTREAM`, `PROXY_BRIDGE_BRIX`, `PROXY_PURE_NGINX_PROXY`, `CREDENTIAL_BRIDGE` | 11183–11215, 12501 |
| Cluster data plane | `CLUSTER_*` (redir/ds/meta/sub/leaf/select/slots/try/esc) | 11160–11199 |
| Cluster CMS control plane | `CLUSTER_*_CMS`, `CMS_TEST_*`, slots DS | 12399–12608 |
| Chaos tiers | `CHAOS_TIER{1,2,3}`, `CHAOS_DISCOVERY_{REDIR,DS}` | 11163–11168 |
| HTTP cache / VOMS | `NGINX_HTTP_CACHE`, `NGINX_WEBDAV_VOMS` | 18457–18458 |
| Compression | `COMPRESS_WEBDAV`, `COMPRESS_S3` | 12960–12961 |
| Interop lab | `INTEROP_OUR`, `INTEROP_OFF` | 21200–21201 |
| Ladder-overflow singles | `CLUSTER_SELECT_REDIRECT`, `CLUSTER_TRY_FIRST` | 29000–29001 |

Dynamic/per-lane ranges are separate: `port_ladder.py` derives them from
`TEST_PORT_START` (default 10000). Documenting the precise interplay
between the fixed defaults above and lane offsets is a TS-0 inventory
item (the fixed constants respond to their own `TEST_*` overrides, not to
`TEST_PORT_START`). The measured floor across every family is 8080 —
nothing in the suite ever needs a privileged (<1024) port, which is the
`LocalBackend` guarantee of §8.2.

---

## Appendix E — Landed-phase record (append on landing; empty at proposal)

| Phase | Landed | Commits | Gate numbers (collect wall/user; soak) | Notes |
|---|---|---|---|---|
| TS-0 | 2026-08-17 | working-tree (no git approval in session) | doc guards green; inventory `--check` idempotent | `dump_suite_surface.py` + inventory md/json + triad; §15 decision note (spellings, pytest.ini, adapter-only verbatim moves) |
| TS-1 | 2026-08-17 | working-tree | deps guard green incl. pyproject manifest; triads 6/6 | pyproject pins two-sided + xdist/crypto/s3 extras; `check_python_deps` learns PEP 621 manifests w/ required>optional>dev precedence + `xdist`→`pytest-xdist` map; `pip install -e BriXTest/` in coverage+asan lanes; import-purity triad |
| TS-2 | 2026-08-17 | working-tree (no git approval in session) | pinning 83/83 unmodified; TS-2 triad 5/5; collect clean 39,617 tests in 22.16s (within guard #9's ≤30s ceiling; 19.1s baseline predates the suite growing to 39.6k and was re-measured under residual concurrent-session load); real-fleet round trip 11/11 in 263s + xdist `-n 2` 16/16 in 258s, both in migration lane 23000, zero leaked ports/procs | Option F partition (§15 note): part4 + per-test hooks + `_check_server_reachable` + tracer + part5 fixture tail + conftest_mu → `brix_suite.harness.{kill_tracer,sentinel,fixtures}` + `harness_ext`; parts 2/3/5-hooks stay exec-composed for pinning-suite patch-transparency; tracer single-install ends the double-wrap; guard #8 early; ~850 exec-composed lines → 1,014 packaged; surface inventory 247 modules |
| TS-3 | 2026-08-18 | working-tree (no git approval in session) | pinning 72/72 unmodified in 195s (the full collection of the four pinning files — 71 test functions + 1 parametrization; TS-2's 83 counted a wider set, nothing was deselected); TS-3 triad 20/20 + TS-2 5/5 + surface 3/3 + packaging 4/4 = 32/32 in 30.4s; real-fleet round trip 7/7 in 112s and xdist `-n 2` 27/27 in 232s, both in isolated lane 15000 (`/tmp/xrd-test-ts3-lane`), zero leaked listeners/processes; **(that round trip was measured, not committed — it is re-runnable only from 2026-08-18's `test_ci_ts3_settings_live_lane.py`; and lane 15000 was mis-spaced, sitting inside the default lane's own 18505-port span — see the follow-up note in §15)**; guards #3 + ports-doc + surface `--check` + import-direction + file-size + deps + namespace all green; collect budget re-measure DEFERRED (39,694-39,708 tests in 40.6-49.8s under load 14-19 from five concurrent sessions, and the collected count moved between the two runs; `settings` imports in 77ms, bounding TS-3's share of the budget) | settings body moved VERBATIM - `brix_suite/settings_values.py` sha256 `10f6d957...` is byte-identical to `git show HEAD:tests/settings.py`, and so is the `_legacy/settings_flat.py` rollback anchor; `tests/settings.py` is a §10.2 self-replacement shim; `SuiteSettings`/`PortLedger` (aliases + attribute access) in `brix_suite/settings_model.py`; guard #3 `check_shim_completeness.py` + append-only baseline (260 names, zero missing); `dump_suite_surface.py` follows shims by subprocess introspection (248 modules); `check_ports_doc.py` rewritten onto the ledger after the shim made its regex pass vacuously; foreign-lane refusal single-sourced in `brixtest.config.lanes`; §15 note has the reasoning |
| TS-4 | 2026-08-18 | working-tree (no git approval in session) | **Pinning, unmodified throughout:** registry 30/30 (incl. the caller-site assertion); prep/declares/orphans 24/24 (`test_fleet_prep_cache` 5, `test_fleet_declares` 11, `test_fleet_teardown_orphans` 8) — the decisive number for item 6, since all five module-dict monkeypatches had to survive the shim; fleet-facing 63/63 against a live 126-instance fleet (`test_server_registry_smoke` 30, `test_fleet_port_uniqueness` 4, `test_conftest_fleet_lifecycle` 29) in 17.8s. **TS gates:** 100/100 across all nine gate files in 172s (`suite_surface` 3, `ts2` 5, `ts3` 21, `ts4_registry_move` 8, `ts4_kinds_and_nginx_tools` 13, `ts4_catalogue_merge` 14, `ts4_launcher_and_deploy` 13, `ts4_kind_ladder_flip` 9, `ts4_prep_and_declares` 14). **Phase soak** (3× boot/stop, isolated lane 30500, `/tmp/xrd-test-ts4-soak`): 126 instances launched every cycle; start-all 27.05/24.56/31.06s, stop-all 18.75/17.42/103.04s (the third under host load avg 23, not a regression — the item-5 round trip measured a second stop-all at 0.82s on the `_quiescent` fast path); zero leaked listeners across the lane's named ledger (30501–32596) before and after all three cycles; `status` snapshots structurally identical across cycles (PID-only diffs); **`find_orphans` reports 0 orphan fleet processes for both the soak and verify lanes** — the authoritative check, since the port window and the `pgrep -af` count the soak script used were both later measured to lie (§14 step 6 now carries the corrected recipe and the evidence). **Guards:** #3 OK at 15 shims, surface inventory 248 modules with `--check` idempotent. The host-literal guard is **green on TS-4's surface**: 7 passed in 22.7s on a correctly-spaced lane (`TEST_PORT_START=19000`, `TEST_SKIP_SERVER_SETUP=1`), with its one failure listing 4 literals in three *untracked* files from concurrent phase-104/audit16v work (`test_audit16v_tpc_off_arms.py`, `test_cvmfs_ingest_oracle.py`, `test_rpm_mirror_dnf.py`) — none of which imports `brix_suite`, and one of which was rewritten by the other session 43 minutes after the last TS-4 edit. That is the decay `host_literal_migration_complete` already flags, not a regression. Its *earlier* failure was two unrelated mistakes, both now fixed in §14: `TEST_REGISTRY_START=0` is not the fleet-skip switch (`TEST_SKIP_SERVER_SETUP=1` is), so the run booted a 126-instance fleet into a host that was concurrently leaking 108 processes; and the lane it booted into was spaced by hundreds of ports when a lane reserves 18480. | Items 1–7 landed, with **item 4 landed as *built and pinned, not installed*** — the launcher package is byte-for-byte equal to the flat stack but `server_launcher.py` stays the live module, because the pinning suite rebinds four names in its module dict and a split package makes those rebinds invisible; the install is carried on TS-7 and pinned meanwhile by `test_ci_ts4_launcher_and_deploy.py`. **Item 8 (ports consolidation) deferred** to its own mini-design — `fleet_ports_shared_phase5.py` and `port_ladder.py` were observed being edited by a concurrent session *mid-run* (guard #3 broke on a 810-vs-816 allocation count and recovered untouched), which is the deferral rationale rather than a hypothetical. Item 5 flipped four kind ladders onto `LAUNCHER_KINDS` rows (`start`/`_quiescent`/`stop`/`_stop_from_disk`); no `spec.kind ==`/`in` comparison remains in any mixin, and its triad is behavioural rather than static because the characteristic failure — a wrong attribute name on a row — imports cleanly and raises only at real teardown (`pidfile_relpath` did exactly that). Item 6 moved prep/declares/orphans behind §10.2 flat-to-flat shims; `TESTS_DIR` was the **fifth** move-hazard instance and the first live one. §15 carries six decision notes (items 1, 2+3, 7, 4, 5, 6) plus the `test_fleet_liveness` finding: its timeout is 756 per-port `ss -ltnp` calls (≈310s) inside a 120s budget, not a crash-looping fleet — the same detector driven by `listening_port_pids()` reports **126/126 live, none crash-looping, in 27.4s**. Sampler swap is entered on TS-7, where editing pinning code is allowed. |
| TS-5 (security/tokens) | 2026-08-18 | working-tree (no git approval in session) | TS-5 tokens gate 21/21 in 9.2s; all nine earlier gate files + the two fleet-facing pinning files re-run **unmodified** at 131/131 in 25.6s; the 25 forge-consuming test files collect clean at 212 tests in 11.4s; guard #3 OK at 22 shims; file-size and `compileall` green. Parity measured before the gate was written: 83 methods before, 83 after, **zero missing, zero extra, zero differing bodies** (AST body hashes against the seven `_legacy/*_flat.py` archives). CLI artefact set is byte-for-byte the same six files as the reconstructed flat stack (`jwks.json`, `jwks_multi.json`, `scitokens.cfg`, `signing_key{,_2,_ec}.pem`), from both `python3 tokenforge.py` and `python3 -m brix_suite.security.tokens`. | `tokenforge.py` + `tokenforge_part{2,3}.py` + the four `_tokenforge_part2_mixin*` slices → `brix_suite.security.tokens` (`jose`, `issuer_cfg`, `mint`, `signing`, `claims`, `manifest`, facade); mixin D held only `aud_any` and merged into `claims`. Seven §10.2 shims, so all seven flat spellings and the package are ONE module object. **The move surfaced two live defects that the `exec` composition had been hiding, both of the same class** — a slice `exec`-ed into its parent's globals may use names its own file never imports, and the reference only becomes a `NameError` once the slice is a real import. (1) `header_jwk_injection` called `_rsa_jwk`, defined in `tokenforge.py` and not in the mixin that used it, so the RFC 7515 §4.1.3 / rules 29/150 vector **could never be minted** and `test_wlcg_token_conformance_headers.py` HDR-11 and `test_wlcg_token_conformance_parity.py` were asserting nothing about embedded-`jwk` rejection; one `jose` module imported by all three class modules fixes it, and the method now returns a 1196-char three-segment JWS whose embedded key is provably not the configured one. (2) The CLI lived in a bare `if __name__ == "__main__":` at the foot of `tokenforge_part3.py` and fired only because part 3 saw its parent's `__name__`; under real imports it never fires, and `fleet_artifacts` additionally reached `write_scitokens_cfg` across the same seam. `prep_steps.FleetArtifactsStep` runs that CLI with `tolerate=True, quiet=True`, so the moved stack **exited 0 while writing nothing** — every fleet would have booted without `jwks_multi.json` or `scitokens.cfg` and no step would have said so. Fixed by giving the CLI a named `manifest.main()` that both the shim and a new `tokens/__main__.py` call. The gate carries a static scan for the defect class itself (`test_no_module_reaches_a_name_it_never_binds`), which is what found (2)'s second half. Remaining TS-5 clusters (x509, pki, kdc, clients, servers, mesh/perf/interop, cli, _legacy) not yet started. |
| TS-5 (security/x509) | 2026-08-18 | working-tree (no git approval in session) | **Pinning, unmodified:** `test_x509forge_selftest.py` + `test_x509forge_v2_selftest.py` 6/6 both sides of the move — 155.7s before, 171.1s after. TS-5 x509 gate 11/11 in 7.7s; guard-#10 negative suite 7/7 in 0.9s; **all eleven gate files plus the two fleet-facing pinning files 170/170 in 24.3s**. The 15 x509-consuming test files collect clean at 354 tests in 3.2s and all 16 non-test consumers (the nine `clauses/` modules, `c_auth_units`, `ocsp_responder`, `mint_delegation_certs`, `wlcg_conformance_fleet`, both differentials, `fleet_ports_shared_phase5`) import unchanged. Parity: 49 definitions before, 49 after, **zero missing, zero extra, zero differing bodies** by AST body hash against the three `_legacy/x509forge*_flat.py` archives. Guards #3 (25 shims), #10, file-size, import-direction, ports-doc and doc-paths all green. | `x509forge.py` + `x509forge_part{2,3}.py` → `brix_suite.security.x509` (`constants`, `primitives`, `cadir`, `scenarios`, `catalogue`, `matrix`, facade, `__main__`), three §10.2 shims, so all four spellings are ONE module object and the 38 consumers stay untouched. `_cad_expired_ca` was stranded at the head of shard 3 purely by shard 2's line budget and is filed with the other four `_cad_*` builders. The six prelude constants had **18 assignments across the three shards** (3×6, identical values, each shard silently overwriting the last in load order) and now have six, in `constants.py`. Four cross-shard references (`CA_DN`, `_openssl_hashes`, `_symlink`, `_key`) became real imports; the static dangling-name scan carried in the gate is what found them. **Guard #10 — `tools/ci/check_shard_entrypoints.py`, wired into `guards.yml`.** The `__main__`-in-a-shard trap that cost TS-5 two defects is not rare: a tree sweep found **13 further modules** carrying it (`cmdscripts/{brixcvmfs_live,c_auth_units,c_regression_units,client_features,cvmfs_driver_units,cvmfs_live_ext,fwd_matrix_live,gsi_trust_live,pblock_live,tap_proxy_live,tpc_fwd_live,user_backend_cred}.py` and `load_test.py`), all correct *while still exec-composed* and all silently broken by a package move. The guard pins that pairing rather than the practice: it fails only when a shard keeps its `__main__` guard after its parent stops composing it. It takes `--root` so its negative suite proves it fires against scratch trees — never the real one. Two findings from building it: `cmdscripts/operator_runtime.py` open-codes the same composition with an inline `exec(..., globals())` loop and had to be recognised (first false positive), and `userns/e2e_redteam_part77.py` is a **true positive** — reached by `from … import *`, so its entry point already cannot fire, consistent with that suite being separately recorded as inert. It is allowlisted by name, with the reason, rather than dropped. Remaining TS-5 clusters (pki, kdc, tokens/x509 vector differentials, clients, servers, mesh/perf/interop, cli, _legacy) not yet started. |
| TS-5 (security/pki) | 2026-08-18 | working-tree (no git approval in session) | TS-5 pki gate 8/8 and the new generator-stamp gate 7/7 in 5.8s; **all seven TS-4/TS-5 gate files plus the two fleet-facing pinning files 75/75 in 16.6s**; guards #3 (26 shims), #10, file-size, import-direction, ports-doc and doc-paths green. Parity: 4 definitions before, 4 after, zero differing bodies by AST body hash against `_legacy/pki_helpers_flat.py`. The move is checked at the output, not the import: `openssl verify` chains both the host and user certificate to the forged CA, the CA carries `CA:TRUE`, the proxies are minted and the CRL is emitted. | `pki_helpers.py` → `brix_suite.security.pki`, one §10.2 shim. Ten call sites, **six of them by string from a subprocess** (`python -c "from pki_helpers import blitz_test_pki; blitz_test_pki()"` in `lib_py/pki`, `resilience/servers` and four `cmdscripts` live drivers) — invisible to any import rewrite, which is why the flat spelling stays a live shim. Two deliberate deviations from verbatim, both pinned: `ROOT_DIR` walks three parents instead of one (left alone, `MAKE_PROXY` and `MAKE_CRL` would point into a `tests/utils` that does not exist — the CRL step is guarded by `.exists()` and would have gone *silent*, so every revocation test would have run against a PKI with no CRL), and the settings import names `brix_suite.settings`. **The plan's premise for this cluster was wrong and is retired in §TS-5:** the inventory read three same-named `regenerate_pki`s as one duplicated function; measured, they are three different functions with three different fates (generator → moved; `lib_py/pki` → `_legacy`, its only consumers being `pblock_live{,_part2}`, `lib_py/nginx` and the already-`_legacy`-bound `dedicated.py`; `prep_steps.regenerate_pki` → stays, monkeypatched at 5 sites across 2 pinning files that NG1 puts out of reach until TS-7). `mint_delegation_certs.py` is a `sys.argv` CLI invoked by path, not a library, and moves to the `cli/` cluster instead. **Two defects found while measuring.** (1) The fleet-prep cache was stamping `tokenforge.py` — which *this phase's own earlier move* had turned into a shim — so edits inside `security/tokens/` no longer busted the cache and a lane could restore a token tree minted by the previous generator, every sentinel file present and every mtime plausible. `_GENERATOR_SOURCES` now expands a package to its modules and the stamp key carries the parent directory (the sources stopped being siblings); `test_ci_ts5_generator_stamps.py` pins it as a rule — *no generator source may be a §10.2 shim* — so it fails at the next move rather than after it. (2) `prep_steps.regenerate_pki` claimed `blitz_test_pki` "keys off `PKI_DIR` in the environment"; it does not — `settings.PKI_DIR` is `TEST_ROOT/pki` fixed at import and `SuiteSettings.pki_dir` ignores `legacy_pki_dir` entirely — so the env dance steered nothing. Comment corrected and the step now warns when the requested and actual targets diverge, instead of blitzing a tree nobody asked about. Also: `brix_suite/__init__.py` now bootstraps `brixtest/src`, because importing the adapter by its *canonical* name from a bare `python -c` was the one spelling that failed. Remaining TS-5 clusters (kdc, tokens/x509 vector differentials, clients, servers, mesh/perf/interop, cli, _legacy) not yet started. |
| TS-5 (security/kdc) | 2026-08-18 | working-tree (no git approval in session) | TS-5 kdc gate 8/8 in 1.7s (the realm provision itself measures 0.63s), the nine `kdc_helpers`-importing test files collect clean, and the catalogue's own invocation shape — `[python, tests/kdc_helpers.py, …]`, absolute path, **no** `PYTHONPATH`, cwd `/` — is exercised as a test rather than assumed. Parity: 17 definitions before, 17 after, zero missing/extra/differing by AST body hash against `_legacy/kdc_helpers_flat.py`. Guards #3 (27 shims), #10, file-size, import-direction green. | `kdc_helpers.py` → `brix_suite.security.kdc`, one §10.2 shim. Three properties made this riskier than its 367 lines suggest, and each is now pinned. (1) The spec catalogue starts it as a **script by absolute path** (`start_argv`/`stop_argv` in `brix_suite/catalogue/support.py`), so `sys.path[0]` is the script's own directory and nothing else is on the path — the module self-locates, and that self-locate is a `__file__` walk, i.e. the move-hazard class again; it now walks two parents and the gate asserts the *effect* (tests/ on `sys.path`) rather than the literal. (2) The cross-process realm lock lives in module state (`_realm_lock_fd`), so two module objects would mean two locks and two ideas of whether the realm is up — the §10.2 shim is load-bearing here, not a convenience. (3) The CLI's exit-code contract (0 = realm up, **3 = cleanly skipped, no MIT tooling**, else error) is read by the caller to decide whether to start the nginx krb5 instance; a stranded `__main__` guard would have exited 0 and started the tier against a realm that was never provisioned, so the shim calls `main()` by name. The security-negative is the one the krb5 tier never asserts for itself: **isolation from the host realm**. `_env()` is the single place the child environment is built, and if it stopped overriding `KRB5_CONFIG`/`KRB5_KDC_PROFILE` every `kinit` and `kadmin` would silently read `/etc/krb5.conf` and succeed against whatever realm the host is joined to. The gate sets both variables to the host paths and proves the module overrides them; a second test provisions a real realm in a private `TEST_ROOT` (never the session's — `provision()` rmtree's the realm, and the daemon is deliberately not started so no ladder port is bound) and reads the exported keytab with `klist -k`: the service principal must be present and **every** principal must end in the test realm. | 
| TS-5 (security/differentials) | 2026-08-18 | working-tree (no git approval in session) | TS-5 differentials gate 25/25 and the guard-#11 negative suite 10/10 in 1.9s; **all ten gate files plus `test_fleet_prep_cache.py` and the three opt-in `cmdscripts` wrappers 118 passed / 3 skipped in 15.13s** (the 3 skips are the tier's own `TEST_TOKEN_DIFF` / `TEST_X509_DIFF` gates, unchanged). Parity by AST body hash against the three `_legacy/*_differential_flat.py` archives: 4/6/4 definitions before, **zero lost, zero differing bodies, and `main` the only addition** in each. All three FINDINGS paths verified to resolve to the committed files under `docs/10-reference/`. Guards #3 (30 shims), #10, **#11**, import-direction, file-size, ports-doc and doc-paths green; surface inventory regenerated (248 modules) and `--check` idempotent. | `token_differential.py` → `brix_suite.security.tokens_vectors`, `x509_differential.py` → `.x509_vectors`, `x509_matrix_differential.py` → `.x509_matrix_vectors`, three §10.2 shims. **Three modules, not the two the mapping table planned** — the two x509 drivers share a shape and nothing else (named hostile scenarios against a per-credential `WlcgInstance` vs the clause matrix against one `ConformanceFleet`), so merging them would have produced one module with two disjoint halves and two FINDINGS paths; the table now records that. Each `__main__` block carried real logic (argv parsing plus the exit code) and became a named `main(argv=None)`, called from the shim: all three are invoked **by absolute path** from a `cmdscripts` runner whose pytest wrapper SKIPs unless an opt-in env var is set, so a stranded entry point here would have exited 0 having replayed nothing and been reported as a pass. Four move hazards fixed: `token_differential`'s `sys.path.insert(dirname(__file__))` self-locate, and all three `FINDINGS` walks — each would have written the published findings table into `tests/brix_suite/docs/10-reference/`, a directory the writers `mkdir` for themselves, so nothing would have raised and the report would simply have stopped being updated. **Guard #11 — `tools/ci/check_shim_entrypoints.py`, wired into `guards.yml`** — generalises that: an archive with a `__main__` guard obliges the live head of its stack to run one. Its first run **found a pre-existing stranded CLI**: `tests/fleet_prep.py` had been a script since the bash fleet was retired, and TS-4 left its guard behind in `brix_suite.prep_steps`; `prepare()` is now `prep_steps.main()` and both spellings call it. The tier's spec-first asymmetry is pinned by test rather than by comment: our verdict disagreeing with the spec must exit 1, a stock-XRootD divergence must not, and the findings writers must still mark an upstream accept of a revoked EEC with ⚠. Remaining TS-5 clusters: clients, servers, mesh/perf/interop, cli, `_legacy` — **not** `clauses/`, which Appendix A holds out of scope until TS-7 and which this row listed in error. |
| TS-3 (real-fleet proof) | 2026-08-18 | working-tree (no git approval in session) | live-lane gate 13/13 in 7.3s serially, and green under `--dist=loadgroup` at both `-n 2` (34/34 in 14.9s) and `-n 4` (34/34 in 19.0s) alongside the hermetic TS-3 file; three consecutive serial runs clean with zero residue (`find_orphans` empty, tree wiped); **all seventeen TS gate files plus `test_fleet_prep_cache.py`: 215 passed in 29.8s**; guards #3 (30 shims), #10 (14 entry points / 56 shards), #11 (7 archived CLIs), import-direction, file-size, ports-doc and doc-paths all green; surface inventory `--check` idempotent. | `tests/test_ci_ts3_settings_live_lane.py` (459 LOC) makes the row above re-runnable: one real `main` nginx in a lane of its own, booted through the same three calls `start-all` makes, restricted to one spec — ~8s, not the 112s a full fleet costs. It pins what hermetic tests cannot reach: the kernel's bound set agrees with `SETTINGS.ports` **and the holding pids are the lane's own**; the import-time side effects (TEST_ROOT republish, TMPDIR pin, ladder rebase + env republish, including the `TEST_*` compatibility spelling) fired in a child importing settings fresh in a foreign lane; the conftest lane gate driven by a live socket — own-and-complete **attaches without wiping** (asserted with a sentinel file in the tree), foreign **refuses and leaves the listener running** (asserted against the pids, not the promise), the refusal names the port the lane *really* bound, and `TEST_SKIP_SERVER_SETUP=1` does not buy a way past it; and ownership-based leak accounting including the nginx worker whose own command line never names the lane — the process `pgrep -af "$LANE"` misses while it counts the shell that ran it. **Two findings, both invalidating advice elsewhere in this plan.** (1) §14's lane tiling ignores `ip_local_port_range`: the derived top tile (47029) failed `bind()` EADDRINUSE on a host where `ss` showed the port free, because 32768..60999 belongs to *outbound* sockets; the documented third tile (37983) is entirely inside it and the second tile's mock pool crosses into it, so only ONE full lane fits below the ephemeral floor on a default Linux host. The file reads the range from `/proc` and derives its base from it. (2) `serial` does not keep a module on one worker under `--dist=loadgroup` — the marker is applied in `pytest_collection_modifyitems` on each *worker* while the controller schedules on the `@group` nodeid suffix, which conftest appends by hand for `cvmfs-fixed-ports` and `ci-guards` and never did for `serial`. The split put two module fixtures on one lane; one wiped `pki/` mid-generation and the boot died on a half-built CA **with no warning**, because the artifact sentinels are checked when a snapshot is stored, not after generation. The file holds its lane under an exclusive `flock` and a test proves, from a child process, that a second owner is refused; making `serial` authoritative is TS-7 work. |
| TS-5 (clients) | 2026-08-18 | working-tree (no git approval in session) | TS-5 clients gate 26/26 in 8.6s and the extended guard-#11 negative suite 11/11; **all eighteen `test_ci_ts*.py` gate files plus `test_fleet_prep_cache.py` at 242 passed in 39.8s**; the 18 XrdCl/http/gsiftp/pty-consuming suites collect clean at 202 tests in 42.5s. Parity by AST body hash against the six `_legacy/*_flat.py` archives: **49 definitions before, 49 after, zero lost, zero extra, zero differing bodies**; the static dangling-name scan over both new packages is clean. **Proved live, not just imported:** an end-to-end smoke through the shadow `XRootD` package parsed a real `XrdCl::URL` and returned a real server verdict, and the fleet-facing pinning file `test_xrootd.py` runs **25/25 in 11.6s** against the attached fleet with its fixtures reported as `brix_suite.clients.xrdcl.proxies.FileSystem`. Guards #3 (35 shims), #10 (14/56), #11 (8 archived CLIs), import-direction, file-size, ports-doc, doc-paths, python-deps and ratchet-monotonic green; surface inventory regenerated (248 modules) and `--check` idempotent. | `_xrdcl_proxy.py` + `_xrdcl_proxy_part2.py` + `_xrdcl_worker.py` → `brix_suite.clients.xrdcl.{worker_link,results,proxies,worker}` behind a facade; `guard_http_lib.py` → `brix_suite.clients.http`; `gridftp_client_env.py` → `brix_suite.clients.gridftp`; `cli_pty.py` **promotes to core** as `brixtest.clients.pty` (pure stdlib, no settings, no fleet). Six §10.2 shims, six new `_legacy` archives. **The plan's premise — port the layer onto `brixtest.clients.procworker` — is retired in §TS-5.** `procworker` does deliver the generic tag-correlated protocol, but the grown proxy carries four affordances it deliberately lacks (env resync on mid-session `X509_*` change, GC-safe lock-free handle release, per-op timeout widening, re-raising the binding's *native* builtin exception type), so a rewrite would have been a behaviour change against R10 and the verbatim-bodies rule; the two protocols coexist. **This was the first cluster whose module owns mutable process state, and it broke a guard.** The layer keeps one worker subprocess per pytest process in a module global with a module lock and an `atexit` hook — two module objects would mean two workers and one hook. `worker_link` owns that state; the facade cannot re-export it by value (`from … import _worker_singleton` freezes `None` at import while the owner rebinds it), so the facade serves it through a module `__getattr__` — which never appears in `__dict__`. **Guard #3's probe therefore moved from `vars(mod)` to `dir(mod)`:** under the old probe the one truthful facade failed and a stale copy passed. The gate pins both halves (`test_the_facade_serves_live_state_rather_than_a_copy`, and `test_guard_three_would_have_passed_the_frozen_copy`, which asserts `_worker_singleton` is exactly the name `vars()` would have missed). **Guard #11 had a second defect this cluster exposed:** `_stack_head()` stripped a leading underscore unconditionally — right for `_tokenforge_part2_mixina` → `tokenforge`, wrong for `_xrdcl_worker`, which is simply private and its own head, sending the guard hunting a `tests/xrdcl_worker.py` that never existed. It now asks the tree instead of guessing, and both shapes are pinned. Two move hazards fixed: the worker-script path is data the package carries and a wrong one **fails green** (no exception — the interpreter probe finds no candidate, `real_bindings_available()` returns False and nine XrdCl suites SKIP), now asserted rather than assumed; and the duplicated prelude had 2 assignments across the two archives and now has 1. Security-negatives: the worker must never import the shadow `XRootD` package (it strips every `sys.path` entry carrying `_SHADOW_MARKER` before `from XRootD import client`) and refuses a path advertising one; `gsi_client_env` pins the credential the caller chose at both euid 0 and non-root; `brixtest.clients.pty` neither shadows the stdlib `pty` it imports nor imports anything from the adapter, and `run_pipe` hands the child no terminal and no stdin. **The 11 `TestGSI` failures seen mid-cluster were fleet state, not the move** — reproduced with stock `xrdfs` outside pytest against the same port, traced to fleet servers started 1m47s *before* the PKI was regenerated (the `fleet_key_desync_signature`), and cleared by a fleet restart. Remaining TS-5 clusters: servers, mesh/perf/interop, cli, `_legacy`. |
| TS-5 (servers) | 2026-08-18 | working-tree (no git approval in session) | TS-5 servers gate **21/21 in 14.9s**; **All twenty gate files 259/259 in 123.7s** (`suite_surface` 3, `ts2` 5, `ts3_settings_object` 21, `ts4_registry_move` 8, `ts4_kinds_and_nginx_tools` 13, `ts4_catalogue_merge` 14, `ts4_launcher_and_deploy` 13, `ts4_kind_ladder_flip` 9, `ts4_prep_and_declares` 16, `ts5_tokens_move` 21, `ts5_x509_move` 11, `ts5_pki_move` 8, `ts5_kdc_move` 8, `ts5_differentials_move` 25, `ts5_clients_move` 26, `ts5_servers_move` 21, `ts5_generator_stamps` 7, `ts5_shard_entrypoint_guard` 7, `ts5_shim_entrypoint_guard` 12, `lane_ownership_gate` 11), under `TEST_SKIP_SERVER_SETUP=1` and `-m "not slow"` — that marker is `pytest.ini`'s own PR-gate contract, and the slow tier it excludes here is `test_ci_asan_lane.py`, a full ASan build plus fleet boot at roughly 18 minutes, which is nightly. Two earlier full-gate attempts were killed at 900s and 2400s before that was read rather than guessed at. All eleven guards green: #3 (43 shims, every baseline name still exported), #10 (14 shard entry points, 56 shards scanned), #11 (15 archived CLIs), config-coverage (1014 sources), client-build-coverage (294), import-direction, file-size, ports-doc, python-deps, ratchet-monotonic, doc-paths. Surface inventory regenerated at 248 modules and `--check` idempotent. Parity by AST body hash against the eight new `_legacy/*_flat.py` archives: **36 top-level definitions — 57 counting methods — before and after, zero lost, zero extra, zero differing bodies**; hashes are taken by qualified name so a changed method names itself instead of hiding inside its class. The static dangling-name scan over `brix_suite/servers/` is clean. **Proved by starting them, not by importing them:** `python -m brix_suite.servers.guard_stub_server` serves `stub-ok\n` and reports `hits: 1` through its control API, and `python3 tests/lib/static_origin_server.py` still answers `ORIGIN-OK` as a script — the two spellings this cluster has to keep true at once. | `tests/lib/*.py` → `brix_suite.servers.*` one-to-one: seven stub processes plus `tokenconf`, the WLCG conformance library twenty-five suites import. Eight §10.2 shims stay at `tests/lib/` — that is the spelling those suites, two OCSP audit suites and one `cmdscripts` driver already use — and eight new `_legacy` archives take the total to 43. **Two named deviations, both forced by the destination.** Five modules opened with `sys.path.insert(0, dirname(dirname(__file__)))` purely to reach `settings`: two parents of `tests/lib/` is `tests/`, two parents of `brix_suite/servers/` is `brix_suite`. Left in place it would not have raised — the directory it names exists — the import would simply have failed later and elsewhere. It is gone, `from settings import` became `from brix_suite.settings import`, and the `import os`/`import sys` it had been the last user of went with it. **The four catalogue `proc` specs switched together, not one per commit as planned, because the reason they switch is shared.** A path spawn puts the *script's* directory on `sys.path[0]` — which is what made the self-locate work — while `-m` puts the *current* directory there, so every module spec must name `tests/` explicitly. `_module_env()` in `catalogue/_shared.py` does that, prepending rather than assigning so a lane's own `PYTHONPATH` survives; the gate asserts the failure without it is loud (`ModuleNotFoundError` before the bind) rather than a stub that starts and serves the wrong thing. **`brixtest.stubs.StubServer` (F12) is deliberately not retrofitted onto these seven.** It already carries the lane refusal this phase's security-negative asks for, but these stubs are pinned by suites reading their exact wire responses, so a rewrite would be a behaviour change wearing a refactor's clothes; the base is what the *next* stub is written on. The security-negative is therefore proven from both ends: `StubServer` exits 2 with one line for a port outside its lane and for a non-loopback bind, and a static scan proves none of the seven moved stubs binds a wildcard address. Two guards took damage from the same cause — the first shims to live below `tests/` — and both were fixed rather than worked around: guard #3's `__import__("lib.tokenconf")` returns the `lib` *package*, whose `dir()` is empty, so all 34 baseline names read as dropped (now `importlib.import_module`); guard #11's head resolver looked only at `tests/<name>.py`, so all eight archives read as CLIs with nowhere left to live (now a search over `("", "lib", "lib_py", "cmdscripts")`). Both shapes are pinned separately in `test_ci_ts5_shim_entrypoint_guard.py` — either alone leaves the other free to regress into name arithmetic. `tests/lib/README.md`, which had described the phase-38 `.sh` libraries dissolved when the fleet became pure Python, was rewritten to the current tree. Remaining TS-5 clusters: mesh/perf/interop, cli, `_legacy`. |
| TS-5 (lane-claim gate) | 2026-08-19 | working-tree (no git approval in session) | Lane-ownership gate 11/11 in 187s against a live fleet and in 21s of actual test time — the difference is the complete fleet this legacy conftest boots for a file that declares nothing, not the tests. Re-run inside the twenty-file gate set: **259/259 in 123.7s**. **The pinning suite the reaper answers to, `test_fleet_teardown_orphans.py`, is 8/8 UNMODIFIED with the gate on by default** — the decisive number, since a gate that broke routine teardown would have had to be turned off to ship — and `test_ci_ts3_settings_live_lane.py`, which calls `kill_orphans` on its own proof lane in a module fixture, is **13/13 in 198.0s against a live fleet** with the gate in front of it (the ancestry exemption is what makes that call still legal). Guards #3 (43 shims), #10 (14 shard entry points, 56 scanned) and #11 (15 archived CLIs) green; surface inventory regenerated at 248 modules, `--check` idempotent. | Ask (viii) had a hole in the middle of it. `orphans.owns` decides ownership *within* a root exactly — whole path components, so `/tmp/xrd-test` never reaches into `/tmp/xrd-test-a15aa`, plus the parent-argv rule for the nginx worker whose own cmdline names nothing — and `test_ci_ts3_settings_live_lane.py` proves all of that against a live fleet. Nothing answered the question one level up: **is this root mine?** A lane root is derived from the test file name (`test_audit16aa…` → `/tmp/xrd-16aa`), so a root read off a `ps` listing carries no session identity at all and a busy fleet is indistinguishable from an abandoned one. On 2026-08-19 a root read that way was reaped from this session and took roughly 200 processes of a concurrent run with it. Precision on the wrong boundary is not safety. The fix reads the DECLARATION, not the listing: a harness puts `TEST_ROOT` in its own environment and `/proc/<pid>/environ` says so. `lane_claimants()` returns everyone declaring a root, `live_lanes()` maps the host, and `kill_orphans(..., force=False)` — the default — raises `ForeignLaneError` naming the pids instead of killing them; a harness reaping its own lane is exempt by ancestry, which is why the one production caller (`conftest_part2`, untouchable under NG1) needed no change. **Two narrowings keep it from becoming noise, and the second failed its own test first.** `TEST_ROOT` is inherited by everything a harness shell launches, so the default lane showed 22 live claimants that were a `CodeChecker analyze -j 20` fleet working under `<root>/tmp/` — live in the lane, unharmed by its teardown, and enough to block every routine reap; only *harnesses* gate. And harness-ness is decided per argv token's BASENAME: every path under pytest's own `tmp_path` begins `/tmp/pytest-of-<user>/`, so a raw `"pytest" in cmd` reads the directory a process works in as the program it runs — which is exactly how the first cut passed the harness case and failed the passer-by case in the same test. A gate that fires on the routine case gets `force=True` pasted over it, and then it protects nothing. **The TS-4 verbatim-move pin had to grow a ledger to allow this.** `test_ci_ts4_prep_and_declares.py` asserted set-equality of definitions between `_legacy/fleet_orphans_flat.py` and `brix_suite/orphans.py`; the archive pins the MOVE, not the module's future, and a frozen module is one nobody may fix. It now carries `_ADDED_SINCE_MOVE` and `_CHANGED_SINCE_MOVE` — named entries with reasons, not a superset rule — so a lost or silently edited archived definition still fails, an undeclared addition fails, and an entry that outlived its edit fails as stale. One comparison helper serves both the real pin and its own negative test, so a second caller cannot reimplement a looser one. §7 (ask viii) carries the narrative; `tests/test_ci_lane_ownership_gate.py` is the gate. |
| TS-5 (mesh) | 2026-08-19 | working-tree (no git approval in session) | Mesh cluster gate **42/42**, and 42/42 again under `-m "not slow"` — that second run is the point, see below. Full gate set **351 passed in 270.72s, zero deselected** across twenty-six files (`suite_surface` 3, `ts2` 5, `ts3_settings_object` 21, `ts4_registry_move` 8, `ts4_kinds_and_nginx_tools` 13, `ts4_catalogue_merge` 14, `ts4_launcher_and_deploy` 13, `ts4_kind_ladder_flip` 9, `ts4_prep_and_declares` 16, `ts5_tokens_move` 21, `ts5_x509_move` 11, `ts5_pki_move` 8, `ts5_kdc_move` 8, `ts5_differentials_move` 25, `ts5_clients_move` 26, `ts5_servers_move` 21, `ts5_cluster_move` 42, `ts5_generator_stamps` 7, `ts5_shard_entrypoint_guard` 7, `ts5_shim_entrypoint_guard` 12, `lane_ownership_gate` 12, `fleet_teardown_orphans` 8, `fleet_declares` 11, `fleet_prep_cache` 7, `fleet_ports` 20, `fleet_port_uniqueness` 4). Guards green after the move: #3 **52 shims** (43 + the nine frozen here), #10 14 shard entry points over **58** shards, #11 **17** archived CLIs (15 + the two mesh orchestrators), plus ratchet-monotonic, import-direction, file-size and doc-paths. Surface inventory regenerated at 248 modules, `--check` idempotent. Parity by AST body hash against nine new `_legacy/*_flat.py` archives: **zero definitions lost, zero added, zero bodies differing** — which is the right bar here precisely because both fixes are module-level constants and import lines, so every def body had to stay identical. The seven mesh-consuming suites plus the eight WLCG conformance suites collect clean (176 and 73 tests); `test_fleet_ports.py` + `test_fleet_port_uniqueness.py` **24/24**. **Not verified, deliberately: no mesh was started.** The binaries are present on this host, so `start` would have worked — and `stop_all()` sweeps the fixed band by *port*, SIGKILLing whatever listens in it and pkilling by a `MESH_DIR` pattern, with no notion of whose it is. Starting one to prove a move would have re-entered the exact hazard the lane-claim gate was built for the day before. What could be proven safely was: builders + templates + locator end to end, writing a three-node topology's configs into a `tmp_path` `CMS_MESH_DIR` and asserting the substitution landed and nothing was written outside it. **A confirming re-run of that same set returned `289 passed, 63 errors in 33.10s`, and it was not this move.** The cause is the known shared-basetemp race: a concurrent session's pytest was live in the same `tests/` tree and `/tmp/xrd-test/tmp/pytest-of-<user>/` was gone by the time the log was read, so the errors bottomed out in `os.scandir` on the basetemp root itself and a `nginx`-named process under `tmp_path` took a SIGTERM that `kill_orphans` is asserted not to have sent. Re-run with `--basetemp` outside `/tmp/xrd-test` — the remedy the incident note already prescribes — the two affected files are **12/12**. Recorded here because a 63-error delta on an unchanged tree reads as a regression, and the first instinct is to go looking in the diff. | Nine modules moved one-to-one into `brix_suite.mesh`: `cms_mesh_lib` + its two continuation shards, `hybrid_mesh_lib`, `mesh_config`, the two `*_servers` orchestrators, and the two WLCG fleets Appendix A groups here. Nine §10.2 shims stay at the flat spellings — seventeen suites, the spec catalogue and two port-inventory modules use them — and nine `_legacy` archives take the total to 52. **Both `__file__`-hop hazards were real and both were silent.** `cms_mesh_lib` derived the repo two parents up and `mesh_config` the template dir one; from `tests/brix_suite/mesh/` those land on `tests/brix_suite` and `tests/` — directories that *exist*, so nothing raises. `CLIENT_DIR` would simply have stopped holding `xrdsssadmin-brix` and every sss topology would have **skipped**, which reads as "no keytab tool on this box". Both now come from `brix_suite.settings.TESTS_DIR`, and the gate re-evaluates the old expressions from the new location to show the bad path is present on disk — the demonstration, not the assertion. The three shards moved together because `split_continuation.load` anchors on the parent's `__file__`; the composed namespace is checked rather than assumed, since a dropped loader line imports cleanly and is missing two thirds of the API. The catalogue's two mesh specs switched to `-m brix_suite.mesh.*_servers` and gained `_module_env()` in the same edit, and the gate asserts the failure without it (`ModuleNotFoundError` before any bind). The free-name scan had to be **unioned across the three shards** — run per file it reports every name the parent binds — and `render()`'s call sites are pinned to literals that exist on disk, since the moved body joins its argument onto `CONFIGS_DIR` unchecked and the body is verbatim. **The planned rename to `.cms`/`.hybrid`/`.wlcg` was not done**, and the reason is recorded under the Appendix A rows: a verbatim pin anchors an archive to a destination by name, and the shards are loaded *by filename* from inside a body the same step asserts is unchanged. **One defect found, in the tier itself.** Named `test_ci_ts5_mesh_move.py`, the file matched `_mesh` in `conftest_part3._SLOW_MODULE_HINTS`, and all forty tests were deselected while the gate set reported `310 passed` — a run that did nothing and said so in green. The classifier reads a filename as a workload; its own comment argues over-inclusion is safe because the full suite covers everything, which is true of a slow suite and false of a gate, whose whole job is the fast tier. A scan showed only this file affected, 1 of 29. The conftest is pre-TS-4 and out of reach under NG1, so the file is `test_ci_ts5_cluster_move.py` and carries `test_no_ci_gate_file_is_auto_marked_slow`, which reads the hint tuple out of the conftest rather than copying it and self-catches on the name that caused it. The real fix — mark by something a file declares — is carried to TS-7. Remaining TS-5 clusters: perf/interop/cachemx/util/guards, cli, `_legacy`. |
| TS-5 (cachemx) | 2026-08-19 | working-tree (no git approval in session) | Cachemx gate **27/27 in 19.4s**, nothing skipped — and the *nothing skipped* is load-bearing, see below. Re-run with the five other TS files that a torn tree had reddened: **125/125 in 13.6s**. Guards after the move: #3 **57 shims** (52 + the five frozen here), #10 and #11 **unchanged at 14/58 and 17** — correctly, since no module in this cluster has a `__main__` guard, and a count that moved would have meant one grew a CLI. `check_import_direction`, `check_file_size`, `check_doc_paths`, `check_ratchet_monotonic` green. Surface inventory regenerated at 248 modules, `--check` idempotent. Parity by AST body hash against five new `_legacy/*_flat.py` archives: **zero definitions lost, zero added, zero bodies differing**. The thirty-three consuming suites collect clean at **2253 tests**. **Four `_FAST` guards fail and none of them is this work:** `check_http_helper_reimpl`, `check_doc_links`, `check_readme_coverage` and `check_template_refs` all point at untracked trees — the phase-104 OCI sources and docs, and another session's in-flight `nginx_audit16ad_inert_config_surface.conf`. Named rather than waved at, because a red guard nobody has attributed is a red guard everyone learns to scroll past. | Five modules moved one-to-one into `brix_suite.cachemx`: `_cachemx`, `_cachemx_grid`, the two calibrated catalogue snapshots and `_cache_partial_helpers`. Five §10.2 shims stay at the flat spellings and five `_legacy` archives take the total to 57. **The same `__file__`-hop hazard as mesh, and the same silence.** `_cachemx` and `_cache_partial_helpers` each derived the repo two parents up to reach `client/bin/`; from `tests/brix_suite/cachemx/` that lands on `tests/brix_suite` — a directory that exists, so no import fails. `_require_binaries()` would then have skipped ~30 suites with *"native client binary missing"*, which reads as an unbuilt client, and `_cache_partial_helpers` would have handed `subprocess.run` a path that is not there. Both now come from `settings.TESTS_DIR`, and the gate re-evaluates the old expression from the new location, asserting the wrong answer is a **real directory** that holds no client tree — the demonstration, not the assertion. **The two catalogue modules needed a different kind of check.** They are literal dicts with no imports and no code, so *every* other property in the file — resolves, is one object, bodies match (it has none) — holds just as well for a copy that lost half its rows. They are therefore checked against each other: HELP and LABEL_KEYS must cover one family set and CONDITIONAL must be a subset of it. **A second defect in the tier, and a general one.** `test_a_missing_client_binary_skips_naming_the_path_it_wanted` was written with `pytest.raises(Exception)`; `Skipped` derives from **`BaseException`** — deliberately, so a broad `except Exception` cannot swallow a skip — so the skip escaped the `with`, escaped the test, and became the test's own outcome. The file read `26 passed, 1 skipped` for a check that asserted nothing, and a stray `1 skipped` is indistinguishable at a glance from the environment-conditional skips the same file legitimately has. Now `pytest.raises(pytest.skip.Exception)` plus a reached-the-end `ran` flag, so a body that stops reaching its assertions fails instead of skipping. Written up with its sibling in `history-testing-and-incidents.md` §15. **Two guard-lane repairs, both of my own making.** `guard_set.prepush_guards()` GLOBS `tools/ci/check_*.py`, so `check_shim_completeness`, `check_shim_entrypoints`, `check_shard_entrypoints` and `check_import_direction` joined the pre-push set the moment each file existed, while `_FAST` — maintained by hand — did not follow: the four TS guards were being run by the hook and asserted green by nothing. `test_fast_lane_covers_the_prepush_guard_set` had been red since TS-2 saying exactly that. Separately, TS-1 added `PYPROJECT_FILES` to `check_python_deps` with a missing-manifest finding and did not teach the synthetic `_deps_tree` fixture to write one, so a guard-lane test failed for a reason unrelated to its own case. Both fixed; `test_ci_guards_b.py` **18/18**. **And a run to distrust.** A gate-set run reddened `ts2`, `ts4_catalogue_merge`, `ts4_prep_and_declares`, `ts5_servers_move`, `ts5_cluster_move` and this file at once, with 13 errors in `ts3_settings_live_lane`. Cause, read off the traceback rather than guessed: `RuntimeError: shared lifecycle ladder expected 857 allocations, found 858` — a **concurrent session editing this same working tree**, caught between its edit to `fleet_ports_shared_phase5.py` and its edit to `port_ladder.py`. The ladder tripwire did its job on a torn read. Re-run after the tree settled: 125/125. Two distinct concurrency modes have now produced regression-shaped results in one day — a wiped shared basetemp and a half-applied source edit — and neither leaves a mark that says *look outside the diff*. Remaining TS-5 clusters: perf/interop/util/guards, cli, `_legacy`. |
| TS-5 (perf) | 2026-08-19 | working-tree (no git approval in session) | Perf gate **30/30 in 1.3s**, nothing skipped. Full gate set **422 across twenty-nine files**. Guards: #3 **61 shims**, #10 **13** shard entry points over **60** shards — that count went *down* by one and that is the deliverable, see opposite — #11 **19** archived CLIs, plus import-direction, file-size, doc-paths and ratchet-monotonic. Surface inventory 248 modules, `--check` idempotent. Parity by AST body hash against four new `_legacy/*_flat.py` archives: **37 definitions before, zero lost, zero bodies differing, `run_cli` the only addition**. **Proved by running them, which is the only proof that means anything here:** `python3 tests/load_test.py --help` and `python3 tests/_perf_ab_helpers.py --help` both exit 0 with their own parsers — the CLI is the thing the move breaks and an import check cannot see it. Better still, `test_perf_netem_bdp.py` **ran the whole netem harness end to end after the move**: it built the `veth` pair, synthesized a 31 ms RTT / 1464 KiB BDP and returned real numbers from both legs, which exercises the one path this cluster was most likely to have silently broken. That test failed once on **magnitude** (ratio 1.2× against a `>= 2.0` floor) when run in a five-file batch and **passed twice standalone** — it is a throughput measurement and cannot share a process; not the move, whose bodies are hash-identical. **Also red and not this work:** `test_server_registry_lint.py` (see opposite), and the seven `test_ci_guards.py` failures, all of which bottom out in the untracked phase-104 OCI tree — `check_duplication` names `src/protocols/oci/` outright. | Four modules moved into `brix_suite.perf`: `load_test` with its two exec-composed shards and `_perf_ab_helpers`. Four §10.2 shims, four `_legacy` archives, taking the totals to 61 and 19. **The driver's entry point was a `__main__` guard in a shard**, firing on the *parent's* `__name__` — `"__main__"` while the parent was a script at `tests/load_test.py`, never again once it is a package module. It is now `run_cli()`, called by name from the shim, and the guard is *removed* from the shard rather than left as a line that reads like an entry point and is unreachable: that is why guard #10's count fell 14 → 13. In a benchmark this failure mode is worse than in a generator — a load test that measured nothing still prints its table headings, and the number missing from the table is the point. **`_perf_netem_helpers` did not move, and the reason is a guard rather than a preference.** It is the third entry in `test_server_registry_lint.LAUNCH_BACKLOG`, keyed by path relative to `tests/`; a move registers a new direct-launcher offender at the new path, a **second in the `_legacy` archive it would create**, and a **stale** entry at the old path — three failures fixable only inside a pre-TS-4 test file NG1 protects. The cluster therefore carries `test_moving_the_netem_harness_would_break_the_registry_lint`, which computes both relpaths and asserts neither is allowlisted, so the deferral is a decision with a proof rather than a module someone forgot. **Leaving it behind is only safe because of the shim**, and the gate pins that too: its `--measure` child does `sys.path.insert(0, dirname(__file__))` then `from _perf_ab_helpers import …`, and that `dirname` is still `tests/`. Had both moved, the same line would have found `_perf_ab_helpers` as a *sibling* — importing fine — and failed one import later on `settings`, inside a child whose non-zero exit `run_ab_over_bdp` converts to `{"available": False}` and the suite converts to a **skip**, in a file that legitimately skips on any host without podman. `netns_bdp_available()` returns True here, so that was a live path and the skip would have been a lie about the host. **One declared deviation from verbatim**: `from __future__ import annotations` on shard 2. `Suite.run_one` is annotated `-> RunStats`, a name shard 1 defines, and without the future import that annotation is evaluated as the class body runs — so the shard raised `NameError` when imported standalone, **as the archived pre-move body still does**. That cost it its shim (guard #3 and `dump_suite_surface` both import a shim's target), which would have made the flat and package spellings two objects for this file alone. The gate asserts both halves — archive still fails, moved copy does not — so removing the line fails here rather than in the guard lane. **And a guard nothing in the loop was running.** `test_server_registry_lint.py` has been red since **TS-4**: the launcher move put the launching body in `brix_suite/launcher/internals.py` and froze a copy at `_legacy/_server_launcher_part2_mixinc_flat.py`, while `INFRA_ALLOW` exempts the old stack **by filename**. Two offenders from a move whose point was that no code changed. It was in neither the gate set nor `_FAST`, so a programme that re-runs its own gates every cluster ran it exactly never — the second instance of that class in two days, after the `_FAST`/`prepush_guards()` glob gap. Written up as §16 of `history-testing-and-incidents.md`, with the general rule: **a guard that scans file content and allowlists by path must exclude `_legacy/` outright**, because an archive is a byte-identical copy and inherits every property such a guard looks for, at a path no allowlist knows — and **when a phase moves modules, the suites to re-run are not only the ones that import what moved**; anything deciding by path is a consumer whose input changed. The fix to that guard is a TS-7 edit. Remaining TS-5 clusters: interop/util/guards (the interop gate cannot be named `test_ci_ts5_interop_move.py` — `interop` is itself a `_SLOW_MODULE_HINTS` substring), cli, `_legacy`. |
