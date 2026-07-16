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
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --pr` | The `not slow` set (~6,990 tests): parallel bulk (`-n12`) + a small serial lane, one flake-filter re-run | **<5min** | The PR gate |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --fast` | Just the parallel bulk (`-m "not slow and not serial"`) — no serial lane | **~4min** | Fastest iteration ("did I break something") |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --nightly` | The deferred `slow` set (~1,770): resilience/chaos/fault-injection, throughput/perf/topology, conformance, clientconf, interop, … | ~8min | Pre-release / nightly CI |
| `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite` | The full 4-lane suite (`--pr` + `--nightly` coverage) with the full flake-rerun ladder | **~10–12min** | The authoritative release gate |
| `PYTHONPATH=tests pytest tests/test_X.py -v` | One file/test | seconds | Focused debugging |

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

Equivalent bare invocation (if you don't want the runner's fleet handling):

```bash
PYTHONPATH=tests pytest tests/ -m "not slow and not serial" -n auto --dist load
```

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

## Triaging a fast-lane failure

The parallel pool occasionally trips a *load-correlated* flake (a ConnectionReset,
a GSI-handshake hiccup). `--fast` already re-runs failures once serially to filter
these. To triage by hand, re-run the failing tests **quiet + serial** — a real bug
fails again, a flake passes:

```bash
PYTHONPATH=tests pytest <failed::tests> -p no:xdist -q
```

## Gotchas

- Counting collected tests: `pytest --co -q` prints a `<Function ...>` tree (because
  `addopts = -v`), so count with `grep -cE '<(Function|Coroutine)'`, not `grep -c '::'`.
- `test_build_hardening::test_module_so_is_relro_now` fails on a **static** module
  build (no `*xrootd*.so` under `objs/`) — it inspects a dynamic module `.so` that
  isn't produced; the nginx binary itself is correctly hardened.
