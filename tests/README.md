# Running the tests

The suite is ~8,700 tests. **Never run bare `pytest tests/`** for a full check — with
no `-n` it runs *serially* and takes 20min+. Use the runner below.

## Scope: native only

`tests/` is for native (non-container) deployments — tests run directly against a
locally built/managed fleet (`manage_test_servers.sh`), optionally pointed at a
remote host via env vars (`TEST_SERVER_HOST` etc.), but never requiring a
container runtime or orchestrator themselves. `tests/ceph/` is the one exception
(it builds/runs some CephFS pieces in-container via `Dockerfile.build`).

The S3/MinIO forwarding tests live in `k8s-tests/remote-suite/tests/` instead
of here: `test_minio_s3_forward.py` (local docker-MinIO fallback + in-cluster
`s3-forward` mode, via `minio_harness.sh`) and `test_s3gsi_multiuser.py`
(in-cluster `s3-gsi` scenario only, no local mode).

Anything that needs Docker, Kubernetes, Helm, or a cluster to run belongs in
`k8s-tests/` instead, not here.

## Quick reference

| Command | What it runs | Time | Use when |
|---|---|---|---|
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --pr` | The `not slow` set (~6,990 tests): parallel bulk (`-n12`) + a small serial lane, single-pass | **<5min** | The PR gate |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --fast` | Just the parallel bulk (`-m "not slow and not serial"`) — no serial lane | **~4min** | Fastest iteration ("did I break something") |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --nightly` | The deferred `slow` set (~1,770): resilience/chaos/fault-injection, throughput/perf/topology, conformance, clientconf, interop, … | ~8min | Pre-release / nightly CI |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite` | The full 4-lane suite (`--pr` + `--nightly` coverage), single-pass with no automatic failure reruns | **~10–12min** | The authoritative release gate |
| `PYTHONPATH=tests pytest tests/test_X.py -v` | One file/test | seconds | Focused debugging |

Select arbitrary server binaries on any suite-runner command with
`--nginx-bin` and `--xrootd-bin`. The runner validates them before collection
and propagates the resolved paths to the registry and dedicated management
helpers:

```bash
TEST_ROOT=/tmp/brix-tests/custom TEST_PORT_START=20000 \
PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite -n 8 \
  --nginx-bin /path/to/nginx --xrootd-bin /path/to/xrootd
```

For an nginx built with `--with-stream=dynamic`, the runner reads its
`--modules-path` from `nginx -V` and automatically loads the stream core,
combined BriX module, and xrdhttp filter when all three are installed there.
For project modules kept elsewhere, pass the two BriX modules. The runner
discovers and prepends the selected distribution's `ngx_stream_module.so` from
`nginx -V`, avoiding Ubuntu/AlmaLinux module-directory differences:

```bash
PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite -n 8 \
  --nginx-bin /usr/sbin/nginx --xrootd-bin /usr/bin/xrootd \
  --nginx-load-module /path/to/ngx_stream_brix_module.so \
  --nginx-load-module /path/to/ngx_http_brix_xrdhttp_filter_module.so
```

**`--pr` + `--nightly` together cover the same tests as the full run.** The split
line is `slow` (auto-applied by module name; see `_SLOW_MODULE_HINTS` in
`conftest.py`). It sits where it does for a hard reason: the shared test fleet
caps useful xdist parallelism at **`-n12`** (`-n16` crashes workers), and the
medium/heavy families (clientconf, conformance, interop) plus the inherently-slow
fault-injection/perf suites (25–59s per test) cannot fit under 5min at that
parallelism. They run in `--nightly` instead.

Both runners clean and start the local fleet for you. Always rebuild first if you
changed `src/` (`cd /tmp/nginx-1.28.3 && make -j$(nproc)`) — the tests run against
the *current* binary.

## The fast tier (`--fast`)

`--fast` runs only the quick tests in parallel, dropping the multi-minute
families (resilience / chaos / conformance / clientconf / mesh / throughput /
interop / …). Those are auto-tagged `slow` in `conftest.py`
(`_SLOW_MODULE_HINTS` + `pytest_collection_modifyitems`) — a single, additive
marker: it does **not** change what the full suite run covers.

It is a fast *signal*, **not** a substitute for the full run: it skips ~1,750
slow tests and doesn't run the dedicated serial/destructive lanes. Run the full
suite before merging.

### `--shards N` — bounded, crash-immune sessions

`suite --fast --shards N` splits the bulk lane into **N independent pytest
sessions** (files bin-packed into balanced shards), each on its own clean fleet:

```bash
PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --fast --shards 6
```

Why: running all ~7,000 fast tests as **one** xdist session exposes a fragile
tail — a single native server/worker crash near 99% makes xdist reschedule the
dead worker's groups and the run can wedge or drag for hours. Sharding bounds the
blast radius: a crash kills **one** shard (which fails fast and is re-runnable),
no session ever reaches the 99% tail of the whole suite, and a shard that trips
the fleet sentinel is isolated — the remaining shards still run. Use it whenever
a monolithic `--fast` run keeps hanging at 99%. (`-n` is capped at 12 and
`--max-worker-restart=8` applies per shard, so a crash-storm aborts that shard
fast instead of spinning.)

Equivalent bare invocation (if you don't want the runner's fleet handling):

```bash
PYTHONPATH=tests pytest tests/ -m "not slow and not serial" -n auto --dist loadgroup
```

**Use `--dist loadgroup`, NOT `--dist load`.** Many suites pin their tests to one
xdist worker via `xdist_group` (e.g. `lc-cachemx`, the `conf_*` interop pairs)
because they share a LifecycleHarness server on a fixed port. `--dist load`
round-robins tests across workers and IGNORES those groups, so several workers
start the same fixed-port server at once and thousands of runs fail with
`bind() … Address already in use`. `pytest.ini` already defaults `addopts` to
`--dist=loadgroup`; do not override it to `load`.

## Pre-push hook (optional)

Install once per clone to run the fast tier automatically before every `git push`:

```bash
tools/git-hooks/install.sh        # sets core.hooksPath → tools/git-hooks
```

Bypass a single push with `git push --no-verify` (or `SKIP_FAST_TESTS=1 git push`).

## Markers

- `slow` — multi-minute families (auto-applied by module name; see `_SLOW_MODULE_HINTS`).
- `serial` — parallel-unsafe (shared mesh/port/timing state); run in their own lane
  and grouped onto one xdist worker via `xdist_group("serial")`.
- `requires_local_server` — writes to the server filesystem; skipped in REMOTE mode.

## Per-test timing ledger

Every pytest session writes a machine-readable timing ledger at session end
(hook in `conftest_part5.py`): `$TEST_ROOT/timings/tests-<UTC>-<pid>.jsonl`
and `.csv`, one row per test with `setup`/`call`/`teardown`/`total` seconds,
outcome, and xdist worker, sorted slowest-first. Under xdist the controller
aggregates all workers into one ledger. To find drill-down targets (budget:
no test over 10 s total):

```bash
awk -F, 'NR>1 && $1+0 >= 10' /tmp/xrd-test/timings/tests-<latest>.csv
```

An interrupted session (Ctrl-C mid-run, killed worker) writes no ledger —
only complete sessions produce one.

## Triaging a fast-lane failure

Every lane is single-pass: the runner never automatically reruns a failed test.
Use the first failure report and the per-instance logs below `TEST_ROOT` to fix
the defect directly. A focused manual invocation remains available when needed:

```bash
PYTHONPATH=tests pytest <failed::tests> -p no:xdist -q
```

## Fleet ownership (`TEST_OWN_FLEET`)

Default: **attach** to a healthy fleet already up (no wipe / start-all /
stop-all / rmtree), so a nested pytest — one spawned by a test — never wipes the
shared fleet its parent owns. `TEST_OWN_FLEET=1` forces a clean wipe+restart of
this lane. (`TEST_SKIP_SERVER_SETUP=1` is separate: it skips fleet setup
entirely for a single already-launched instance.)

## Gotchas

- Counting collected tests: `pytest --co -q` prints a `<Function ...>` tree (because
  `addopts = -v`), so count with `grep -cE '<(Function|Coroutine)'`, not `grep -c '::'`.
- `test_build_hardening::test_module_so_is_relro_now` fails on a **static** module
  build (no `*xrootd*.so` under `objs/`) — it inspects a dynamic module `.so` that
  isn't produced; the nginx binary itself is correctly hardened.
