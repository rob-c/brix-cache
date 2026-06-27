# Client-Tools Conformance Suite — Design

**Date:** 2026-06-26
**Status:** Approved design (pre-implementation)
**Owner:** client-tools
**Scope:** ~1,000 conformance tests for the project's re-implemented XRootD client tools.

---

## 1. Goal

Prove that the project's re-implemented client CLI tools (`client/bin/*`) are
**behaviourally compatible with the stock XRootD client tools** (`/usr/bin/xrd*`),
**while explicitly allowing and pinning the deliberate additions** (extra
functionality, knobs, tunings) the project's tools provide.

"Compatible" is enforced, not aspirational: any difference between our tool and
the stock tool must either (a) be byte/exit-code identical, or (b) be a
**registered, labelled divergence** with a documented reason and a pinned
expectation. An *unregistered* difference is a test failure.

### Three test layers (all in scope)

1. **Differential parity** — run our tool and the stock tool with identical
   arguments against the same server; assert exit-code/output/byte parity
   (subject to the divergence registry).
2. **Behavioural / golden** — for project-only features (no stock oracle),
   assert the observable effect of the feature.
3. **CLI-surface conformance** — every stock flag/subcommand is accepted with
   stock semantics; our extra flags are enumerated and documented.

### Guiding rule for extra knobs

> **Knob-off ⇒ differential parity. Knob-on ⇒ behavioural.**

When a project-only flag is absent/default, the tool must be byte-for-byte
identical to stock. When the flag is engaged, the suite asserts its documented
behaviour **and** the correctness invariant that engaging the knob does not
change transferred bytes/checksum versus the knob-off baseline.

---

## 2. Tool scope & priority

Re-implemented tools live in `client/bin/`. Stock counterparts exist on this
host for six tools. We prioritise the stock-backed tools first, weighted to
`xrdcp` and `xrdfs` (the tools with real data/metadata semantics and rich option
surfaces).

**Priority order (this suite):**

1. `xrdcp` — heaviest
2. `xrdfs` — second
3. `xrdadler32`, `xrdcrc32c`, `xrdgsiproxy`, `xrdmapc` — moderate

**Deferred to a later wave** (native-only, no stock binary on host):
`xrd`, `xrddiag`, `xrdprep`, `xrdqstats`, `xrdsssadmin`, `xrootdfs`,
`mpxstats`, `wait41`, `xrdcrc64`.

---

## 3. Server matrix

Client conformance holds the **server constant** and swaps only the **client
binary**, so a divergence is provably client-side. We run the **full endpoint
matrix**, but an applicability filter (Section 6) keeps the cross-product
behaviourally meaningful rather than padded.

Endpoints (from `tests/settings.py`):

| Label | Target | Auth env injected |
|---|---|---|
| `anon` | nginx `:11094` | none |
| `gsi`  | nginx `:11095` | X509 proxy |
| `tls`  | nginx `:11096` | GSI + TLS / CA dir |
| `token`| nginx `:11097` | bearer token |
| `ref`  | reference xrootd `:11098` | per-test |

A case declares which endpoints it applies to; auth-specific cases fan out
across auth ports, pure-local cases (e.g. checksum math, usage text) stay
single-endpoint.

---

## 4. Architecture & file layout

The suite reuses the existing `tests/settings.py`, `tests/conftest.py`, and
server fixtures, and adds a self-contained harness subpackage.

```
tests/clientconf/
  __init__.py
  diffcore.py        # run_client(), NormalizedResult, normalization pipeline, comparison verbs
  endpoints.py       # server matrix + per-endpoint auth env
  divergence.py      # registry loader + assert helpers
  divergence.yaml    # DATA: every intentional our-vs-stock difference (labelled + reasoned)
  flag_inventory.py  # auto-extract stock flag surface from /tmp/xrootd-src
  cases/
    __init__.py
    xrdcp_cases.py
    xrdfs_cases.py
    cksum_cases.py        # xrdadler32 + xrdcrc32c
    xrdgsiproxy_cases.py
    xrdmapc_cases.py
  README.md

tests/
  test_clientconf_xrdcp.py       # parametrizes xrdcp_cases x endpoints through diffcore
  test_clientconf_xrdfs.py
  test_clientconf_cksum.py
  test_clientconf_xrdgsiproxy.py
  test_clientconf_xrdmapc.py
  test_clientconf_surface.py     # flag-inventory coverage assertions
  test_clientconf_narrative.py   # hand-written stateful-scenario layer
```

**Data-vs-shim split:** `cases/*` and `divergence.yaml` are pure data; the
`test_clientconf_*.py` files are thin parametrize-and-assert shims over
`diffcore`; `test_clientconf_narrative.py` is the only procedural file. Each
tool's test count is visible and tunable by editing one table.

---

## 5. Differential core (`diffcore.py`)

### `run_client(tool, args, endpoint, *, env_extra=None, stdin=None, produces=None) -> NormalizedResult`

- Resolves the binary: `STOCK` (`/usr/bin/<tool>`) or `OURS`
  (`client/bin/<tool>`). Called twice per parity case (once each), then
  compared.
- Builds the URL/target from `endpoint` and injects the endpoint's auth env.
- Runs under `subprocess.run` with a per-call timeout and a **scrubbed env**
  (drop ambient `X509_*` / `BEARER_TOKEN`, then set only what the endpoint
  needs — mirrors the existing `_CLEAN_ENV` pattern).
- Captures `(rc, stdout, stderr)` and, if `produces=<path>`, the produced
  file's size + checksum.

### `NormalizedResult`

- `rc` — exact integer; **exit codes are compared exactly, never normalized**.
- `stdout_norm` / `stderr_norm` — produced by a **named, centralized**
  normalization pipeline (a list of `(name, regex, repl)` rules) that strips:
  version banners, build IDs, timestamps, durations, transfer-rate / progress-bar
  lines, PIDs, absolute tmp paths, host-specific strings, ANSI codes; and
  collapses whitespace runs. The raw views are always retained.
- `produced` — `{size, checksum}` or `None`.

### Comparison verbs (the case-table assertion vocabulary)

- `assert_parity(stock, ours, dims)` — `dims ⊆ {rc, stdout, stderr, bytes}`.
  On mismatch, raises with a unified diff of **both** normalized and raw views.
- `assert_bytes_identical(a, b)` — checksum equality for transfers.
- Both verbs **first consult the divergence registry**: if `(tool, case_id,
  dim)` is registered, the verb switches from "must be equal" to "must match the
  registered expectation". An unregistered difference still fails loudly.

**Why centralize:** one normalization pipeline + one comparison path means every
tool agrees on what "the same" means. Raw views are always retained so a
normalization rule can never silently mask a regression — failures show both.

---

## 6. Case tables & parametrization

A **case** is a data row. Test count = `Σ (cases_tool × applicable_endpoints)`
plus surface + narrative tests.

```python
Case(
  id="upload-then-download-roundtrip",
  argv=lambda ep, f: ["-f", f.local, f"{ep.url}/{f.remote}"],
  endpoints=ALL,                 # or a subset label set
  parity={"rc", "bytes"},        # facets that must match stock (knob-off baseline)
  produces="dst",                # what to checksum
  knob=None,                     # or KnobSpec(flag=..., behavioral=fn)
  xfail_endpoints=set(),         # known-unsupported combos -> skip, not fail
)
```

- **Parametrization:** `pytest.mark.parametrize` over `case × endpoint`, with
  the endpoint filter and `xfail_endpoints` applied **at collection** so the
  matrix stays meaningful (no token case against the anon port, no GSI case with
  no proxy). Parametrized ids read `xrdcp[upload-roundtrip-gsi]`.
- **Knob cases auto-expand** into two tests: knob-off (full stock parity) and
  knob-on (behavioural assertion against ground truth/log/counter **plus** the
  invariant that bytes/checksum equal the knob-off result).
- **Applicability filter** is the guard against "full matrix = padding": a case
  fans out across endpoints only where the variation is behaviourally real
  (auth handling, TLS data paths) and stays single-endpoint otherwise.

### Indicative count budget (~1,020)

| Tool | Base cases | × endpoints (avg) | Knob expansions | ≈ Tests |
|---|---|---|---|---|
| xrdcp | ~95 | ×4 | +90 | ~470 |
| xrdfs | ~80 | ×4 | +40 | ~360 |
| xrdadler32 + xrdcrc32c | ~22 | ×2 | +8 | ~55 |
| xrdgsiproxy | ~20 | ×1 | +10 | ~40 |
| xrdmapc | ~12 | ×2 | — | ~25 |
| surface (flag coverage) | per stock flag + extras | — | — | ~40 |
| narrative | stateful scenarios | — | — | ~30 |

1,000 is a **target, not a quota**: low-value rows are trimmed via the endpoint
filter, not padded. Counts are tunable by editing one table.

---

## 7. Divergence registry & flag inventory

### `divergence.yaml`

One entry per intentional difference:

```yaml
- id: xrdcp.help.extra-flags
  tool: xrdcp
  dim: stdout
  trigger: ["--help"]      # arg signature that surfaces it, or "always"
  kind: superset           # superset | replaced | extra-exit-code | format
  reason: "Our --help lists project-only knobs (--retry-policy-x, --uring, ...)"
  expect:
    stock_subset_of_ours: true
    new_lines_must_match: "^\\s*--(uring|...)"
  owner: client-tools
  added: 2026-06-26
```

`kind` taxonomy:

- **superset** — ours = stock output + labelled extras. Assert stock ⊆ ours; the
  *extra* content matches a pinned pattern (new extras can't sneak in
  unreviewed).
- **replaced** — ours deliberately changes a line (e.g. tool name in usage).
  Assert ours matches a pinned regex; stock's exact text not required.
- **extra-exit-code** — ours defines a new rc for a condition stock didn't
  distinguish.
- **format** — same information, intentionally different rendering.

`divergence.py` exposes `lookup(tool, case_id, dim)`, consulted by `diffcore`'s
verbs. **A divergence must be registered to be tolerated.**

### `flag_inventory.py`

Parses stock sources under `/tmp/xrootd-src`
(`XrdApps/XrdCpConfig.cc` for xrdcp; the `XrdCl` admin/query op tables + xrdfs
command help for xrdfs; getopt strings for the small tools) to produce the
authoritative set of stock flags/subcommands. Two consumers:

1. `test_clientconf_surface.py` asserts **every stock flag has at least one case
   in the tool's table** — coverage proven against the real stock surface; a
   rebased `/tmp/xrootd-src` that adds a flag makes the suite report it
   untested.
2. A companion assertion enumerates **our extra flags** and requires each to
   appear in `divergence.yaml` (kind `superset`) — every added knob is forced to
   be documented and to carry knob-off/knob-on tests.

---

## 8. Narrative layer (`test_clientconf_narrative.py`, ~30 tests)

Stateful scenarios a flat table expresses poorly. Each step still uses
`diffcore.run_client`; the file sequences them procedurally:

- **Resume across restart** — partial upload → restart server → resume; final
  bytes == source + parity with stock's resume outcome (uses the `upload_resume`
  port-11118 setup).
- **Multi-stream × retry interplay** — `-S N` with an injected mid-transfer
  fault; recovery + byte-identity.
- **TPC third-party copy** — our-orchestrated vs stock-orchestrated, byte
  parity.
- **Recursive tree upload/download** (`-r`) — mixed-size tree, full-tree
  checksum-manifest parity.
- **Credential lifecycle** — `xrdgsiproxy init → info → use-in-xrdcp →
  destroy`.
- **xrdfs interactive mode** — piped command script vs stock interactive REPL
  output (normalized).

---

## 9. Error & skip handling (uniform)

- **Missing binary:** stock tool absent ⇒ skip that tool's *parity* dimension
  (behavioural/native-only still run). Our binary absent ⇒ build once via
  `make -C client` (module fixture, mirrors `test_native_xrdcp_xrdfs.py`); build
  failure ⇒ skip, never a spurious fail.
- **Endpoint unavailable:** reuse existing server fixtures/readiness checks; a
  down endpoint ⇒ skip its parametrized rows.
- **Timeouts:** every `run_client` is bounded; a hang is a **failure** with
  captured partial output, not a suite hang.
- **Stop on systemic failure:** if the stock binary or an endpoint produces N
  identical infra errors, surface one clear diagnostic instead of hundreds of
  redundant red rows (respects the repo "stop on repeated identical failure"
  rule).
- **Determinism / xdist-safety:** scrubbed env + per-test temp dirs + unique,
  worker-id-namespaced remote paths so the full matrix runs safely under
  `pytest -n`.

---

## 10. Out of scope (this spec)

- Native-only tools (Section 2 deferred list) beyond what surface/divergence
  bookkeeping requires.
- Server-side conformance (covered by the existing `test_conf_*` family).
- Performance/throughput benchmarking (separate perf harness exists).

---

## 11. Definition of done

- Harness subpackage (`tests/clientconf/`) implemented with `diffcore`,
  `endpoints`, `divergence`, `flag_inventory`, and `cases/` for the six
  stock-backed tools.
- ~1,000 collected, meaningful tests (target, not padded).
- `test_clientconf_surface.py` proves full stock-flag coverage and forces every
  project-only flag into `divergence.yaml`.
- Suite is green (allowing documented skips for absent endpoints/binaries) and
  xdist-safe.
- `tests/clientconf/README.md` documents how to add a case and register a
  divergence.
