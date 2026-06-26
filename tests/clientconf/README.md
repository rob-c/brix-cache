# clientconf — client-tools conformance harness

Proves the project's re-implemented client tools (`client/bin/*`) are
behaviourally compatible with the stock XRootD tools (`/usr/bin/xrd*`), while
documenting and pinning the project's deliberate additions.

**Design rule:** *knob-off ⇒ differential parity with stock; knob-on ⇒
behavioural.* An **unregistered** difference is a failure.

Full design: `docs/superpowers/specs/2026-06-26-client-tools-conformance-suite-design.md`.

## Layout

| File | Responsibility |
|---|---|
| `diffcore.py` | Run a tool (stock\|ours), normalize output, compare. `run_client()`, `Result`, `assert_parity()`, `assert_bytes_identical()`. |
| `endpoints.py` | The server matrix (anon/gsi/tls/token nginx + ref xrootd) + per-endpoint auth env + health probe. |
| `corpus.py` | Deterministic seeded data set the read-only cases fan out over. |
| `model.py` | `Case` and `KnobSpec` data types. |
| `runner.py` | `expand()` cases → params; `run_param()` executes parity / knob / skip. `Ctx` per-test scratch + unique paths. |
| `divergence.py` + `divergence.yaml` | Sanctioned-divergence registry consulted by the comparison verbs. |
| `flag_inventory.py` | Live parse of the stock flag/command surface from `/tmp/xrootd-src`. |
| `surface.py` + `surface_map.yaml` | Stock-flag → project-tool classification (same/alias/default/unsupported) + project extras. |
| `fixtures.py` | `clientconf_env` session fixture: build clients, seed corpus, discover healthy endpoints. |
| `cases/*.py` | Per-tool case tables (`CASES`, or `cases_for(tool)`). |

Test shims live in `tests/test_clientconf_*.py` and are a two-line
parametrize over `runner.expand(<tool>_cases.CASES)`.

## How comparison works

For each `(case, endpoint)` the runner runs **stock** and **ours** with the same
argv, normalizes stdout/stderr (named rules in `diffcore.NORMALIZERS`), and
compares the dims the case declares (`rc`/`stdout`/`stderr`/`bytes`). Before
failing on a difference it consults `divergence.lookup()`: a **registered**
difference is asserted positively against its pinned expectation; an
**unregistered** one fails with both normalized and raw views.

## Adding a case

1. Open the tool's table in `cases/`.
2. Append a `Case(id=..., argv=lambda ep, ctx, which: [...], endpoints=...,
   parity={...})`. Use `ctx.local(name, which)` for download sinks and
   `ctx.remote(name, which)` for upload targets (per-binary-unique, xdist-safe).
3. For a read-only op fan it out over `corpus.*_NAMES`.

## Adding a project-only knob

1. Add the flag to `surface_map.yaml` under the tool's `extras` (forces the
   surface test to confirm it is advertised in `--help`).
2. Attach a `KnobSpec(flag, behavioral_fn)` to a representative base `Case`.
   The runner auto-creates the knob-off (parity) and knob-on (behavioural +
   bytes-invariant) tests.

## Registering a divergence

Add an entry to `divergence.yaml` (`kind`: superset / replaced / extra-exit-code
/ format) with a `reason` and pinned `expect`. The comparison verbs pick it up
automatically by `(tool, case, dim)`.

## Running

```bash
PYTHONPATH=tests pytest tests/test_clientconf_surface.py -v          # no server needed
PYTHONPATH=tests pytest tests/test_clientconf_xrdfs.py -v            # needs the fleet
PYTHONPATH=tests pytest tests/ -k clientconf -q                      # whole suite
```

Endpoints that are down — or credentials that are unhealthy (e.g. an expired
token) — cause **skips**, never failures: client parity is never reported red
for an infrastructure reason.
