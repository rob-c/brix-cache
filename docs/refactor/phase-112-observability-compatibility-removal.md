# Phase 112 — Observability compatibility removal

**Status:** IMPLEMENTED — compatibility-window removal phase
**Depends on:** Phase 110 complete and at least one documented release carrying
both the canonical and deprecated surfaces
**Risk:** operator-facing; dashboards, log pipelines and alert rules can break

## Goal

Remove the temporary monitoring aliases and duplicate series retained by Phase
110 after operators have had a real migration window. This is deletion and
consumer migration, not another vocabulary redesign. The canonical variable,
JSON and Prometheus names selected by Phase 110 do not change here.

The phase must not be marked implemented until every registered item in this
document is gone. Two CI rules are intentionally self-deleting: directive rule
R14 and metric rule M2 fail when a Phase-112 document says `IMPLEMENTED` while
an old surface remains.

## Inventory to remove

### nginx variables

| Deprecated | Canonical |
|---|---|
| `$brix_session_dn` | `$brix_dn` |
| `$brix_session_vo` | `$brix_vo` |
| `$brix_session_user` | `$brix_sub` |
| `$brix_session_auth` | `$brix_auth_method` |
| `$brix_session_tls` | `$brix_tls` |
| `$brix_session_bytes_out` | `$brix_bytes_served` |
| `$brix_session_bytes_in` | `$brix_bytes_received` |
| `$brix_cvmfs_cache`, `$cvmfs_cache`, `$brix_oci_cache`, `$brix_rpm_cache` | `$brix_cache_status` |

The first seven are pinned in `tools/ci/directive_registry_allowlist.txt`.
Before removal, search configurations, examples, dashboards, log formats and
tests for every alias. Do not remove an alias merely from the allowlist while a
registration or consumer survives.

### JSON access-log fields

| Deprecated | Canonical |
|---|---|
| `from_cache` | `cache_status` |
| `subject` | `sub` |
| `bytes` | `bytes_served` |
| `latency_us` | `backend_time_us` |

Confirm whether compatibility output emits both fields or uses a versioned
shape before deleting. Update ingest mappings and saved queries in the same
change; a parser silently dropping a field is a failed migration.

### Prometheus metric families

The exact self-deleting registry in `tools/ci/check_metric_naming.py` currently
contains nine families:

- `brix_io_latency_usec`;
- `brix_webdav_bytes_rx_total` and `brix_webdav_bytes_tx_total`;
- `brix_s3_bytes_rx_total` and `brix_s3_bytes_tx_total`;
- `brix_bytes_rx_total` and `brix_bytes_tx_total`;
- `brix_bytes_root_rx_total` and `brix_bytes_root_tx_total`.

Also verify Phase 110's compatibility pair
`brix_cache_hits_total`/`brix_cache_misses_total` against canonical
`brix_cache_requests_total{cache_status}`. If it is still emitted but is not in
the registry, add it to the pre-removal inventory first; do not let an
unregistered compatibility series escape the phase.

**Verified (W1): it escaped.** Both are emitted by
`unified_export.c:unified_emit_cache` — carrying an in-source comment that says
"the two legacy families stay for one release (deprecated, removal phase-112)" —
and neither is in `DEPRECATED_METRICS`, so the M2 self-deleting pin would never
have fired for them. They are hereby part of the inventory: **eleven families,
not nine.** Rather than register them in `DEPRECATED_METRICS` only to delete the
entry in the same change, this phase deletes the families directly and records
the escape here, which is what the registry existed to make visible.

The `# DEPRECATED` note in `stream_family.c` names
`brix_io_bytes_*{proto="stream"}`; that is correct — `BRIX_PROTO_ROOT`'s metric
label is the string `"stream"` (`src/core/types/proto_list.h`), not `"root"`,
which is its *dashboard* name.

## Work plan

- [x] **W0 — release-window proof.** Name the release that first carried both
  spellings and the earliest release allowed to remove them. Record the operator
  migration notice and query/config examples. → [W0](#w0--release-window-proof)
- [x] **W1 — complete consumer census.** Search tracked configs, docs,
  dashboards, tests, ELK/OpenSearch templates, Prometheus rules and Grafana
  expressions. Produce an old-to-new ledger with zero unclassified hits.
  → [W1](#w1--consumer-census)
- [x] **W2 — variable removal.** Delete old registrations and handlers, then
  delete their seven R14 allowlist rows. Unknown old variables must fail nginx
  config validation rather than silently returning `-`. → [W2](#w2--variable-removal)
- [x] **W3 — JSON removal.** Stop emitting deprecated keys, update schemas and
  stored-query fixtures, and assert a canonical record contains each fact once.
  → [W3](#w3--json-removal)
- [x] **W4 — metric removal.** Stop registering and emitting all deprecated
  families, remove compatibility HELP/TYPE text, update dashboards/alerts, and
  delete their `DEPRECATED_METRICS` entries. → [W4](#w4--metric-removal)
- [x] **W5 — documentation.** Remove compatibility-era examples, retain one
  release-note migration table, and update monitoring reference material.
  → [W5](#w5--documentation)
- [x] **W6 — close.** Only after W0–W5, change this document's status to
  implemented. R14 and M2 must remain green after their self-deleting triggers
  activate. → [W6](#w6--close)

## W0 — release-window proof

### The release record

There is no `Unreleased` section in `CHANGELOG.md` and the only git tag in the
repository is `v6.1.0-ref` (the vendored XRootD reference tree, not a BriX
release). The release record is therefore `BRIX_SERVER_VERSION_BARE` in
`src/core/ident.h` plus the top CHANGELOG entry, kept in sync by
`tools/ci/check_version_sync.py`.

**The last cut release is v1.5.0 (2026-08-26), bump commit `201ac9fdb`.** Every
deprecation in this phase was created by phase 110, which landed in `7e2aa0639`
(2026-09-02) — *after* v1.5.0. So the question "did v1.5.0 ship both spellings?"
has a different answer per surface, and the three answers are what this section
records.

### Evidence — what v1.5.0 actually shipped

Each row was checked with `git grep <name> 201ac9fdb -- src`.

| Surface | Deprecated in v1.5.0 | Canonical in v1.5.0 | Group |
|---|---|---|---|
| 7 `$brix_session_*` stream variables | **no** — `src/protocols/root/stream/stream_variables.c` does not exist in that tree | no | **A** |
| `$cvmfs_cache` / `$oci_cache` / `$rpm_cache` and their `brix_`-prefixed twins | yes (they predate phase 106) | **no** — `$brix_cache_status` is absent | **C** |
| 8 byte counters (`brix_bytes_{rx,tx}_total`, `brix_bytes_root_*`, `brix_webdav_*`, `brix_s3_*`) | yes, already carrying their `# DEPRECATED: use brix_io_bytes_*` note | **yes** — `brix_io_bytes_read` / `_written` are emitted | **B** |
| `brix_io_latency_usec` | yes | **no** — `brix_io_latency_seconds` is absent | **C** |
| `brix_cache_hits_total` / `brix_cache_misses_total` | yes | **no** — `brix_cache_requests_total` is absent | **C** |
| JSON `bytes`, `latency_us`, `from_cache`, `subject` | yes — v1.5.0's `access_log.c` emits **only** these | **no** | **C** |

The three groups:

- **Group A — never shipped.** The seven `$brix_session_*` stream variables were
  born deprecated: phase 106 introduced them and phase 110 superseded them, both
  after v1.5.0. No released BriX ever exposed them, so no operator can have a
  log_format that depends on them. Removal here is not a compatibility break; it
  is deleting an alias that only ever existed in-tree.
- **Group B — window served.** The eight byte counters shipped in v1.5.0
  *alongside* their canonical replacement and *with* the machine-readable
  `# DEPRECATED` note in the exposition itself. That is exactly the one-release
  window phase 110 rule 5 asks for. Removable without deviation.
- **Group C — window unserved.** The latency histogram, the cache hit/miss pair,
  the four JSON keys and the four cache variables shipped in v1.5.0 *without*
  their canonical twin. Their canonical twin exists only in the working tree.

### The Group C deviation, stated plainly

Phase 110 rule 5 is "deprecate, never break, for one release", and this
document's own non-goals say "no removal before the release window". Group C
removal violates both **if** the next release is cut before an intermediate
release ships old-and-new together.

This phase removes Group C anyway, for one reason: the deprecated and canonical
spellings for Group C were introduced in the *same* unreleased cycle. There is
no released consumer of `brix_io_latency_seconds` to migrate *to*, and no
released consumer of `brix_cache_requests_total` either — v1.5.0 operators are
using the *old* names, and they must change their queries at the next upgrade
whether that upgrade removes the old names or merely adds the new ones. Carrying
both through a release only defers the same edit.

This is the phase-110 R-6 precedent applied a second time: when one release
carrying both is impossible for a value, the change is called out in the release
notes rather than smuggled through. The obligation this creates is therefore
**editorial, not technical** — the migration table below must appear in the
CHANGELOG entry for the release that carries this phase, under a **Breaking**
heading.

The alternative, if the maintainer prefers to honour the letter of rule 5, is to
cut a release from the current tree first (it already emits every canonical name
beside every deprecated one — that release *is* the window) and land phase 112
in the release after it. Nothing in W1–W6 changes under that choice; only the
release in which the deletion ships moves.

### Operator migration notice

The table below is the notice. It is the one migration table W5 retains, and it
belongs in the CHANGELOG.

**nginx variables** (a stale variable in a `log_format` is a *startup abort*,
not a silent `-`, so this is the surface to fix first):

| Removed | Use |
|---|---|
| `$brix_session_dn` | `$brix_dn` |
| `$brix_session_vo` | `$brix_vo` |
| `$brix_session_user` | `$brix_sub` |
| `$brix_session_auth` | `$brix_auth_method` |
| `$brix_session_tls` | `$brix_tls` |
| `$brix_session_bytes_out` | `$brix_bytes_served` |
| `$brix_session_bytes_in` | `$brix_bytes_received` |
| `$cvmfs_cache`, `$brix_cvmfs_cache` | `$brix_cache_status` |
| `$oci_cache`, `$brix_oci_cache` | `$brix_cache_status` |
| `$rpm_cache`, `$brix_rpm_cache` | `$brix_cache_status` |

```nginx
# before
log_format brixsess 'auth=$brix_session_auth user=$brix_session_user '
                    'vo=$brix_session_vo tls=$brix_session_tls '
                    'out=$brix_session_bytes_out in=$brix_session_bytes_in';
# after — the same names now serve BOTH the http and stream planes
log_format brixsess 'auth=$brix_auth_method user=$brix_sub '
                    'vo=$brix_vo tls=$brix_tls '
                    'out=$brix_bytes_served in=$brix_bytes_received';

# before                          # after
# ... cache=$cvmfs_cache          ... cache=$brix_cache_status
```

`$brix_cache_status` is a superset, not a rename: it renders `HIT`, `MISS`,
`BYPASS`, `NEGHIT` or `-` on every plane, and the per-plane mapping is exactly
what the old variables rendered (cvmfs `HIT`→`HIT`, `FILL`→`MISS`, `NEG`→
`NEGHIT`; oci/rpm hit and local→`HIT`, miss→`MISS`). One field replaces four.

**JSON access-log keys:**

| Removed | Use |
|---|---|
| `bytes` | `bytes_served` |
| `latency_us` | `backend_time_us` |
| `from_cache` (boolean) | `cache_status` (string) |
| `subject` | `sub` |

`from_cache` is the only shape change: a boolean becomes a string, because
`false` conflated `MISS`, `BYPASS` and "not a cache plane". An ingest mapping
that must keep a boolean should derive it as `cache_status == "HIT"`.

**Prometheus families:**

| Removed | Use |
|---|---|
| `brix_bytes_tx_total`, `brix_bytes_root_tx_total` | `brix_io_bytes_read{proto="stream"}` |
| `brix_bytes_rx_total`, `brix_bytes_root_rx_total` | `brix_io_bytes_written{proto="stream"}` |
| `brix_webdav_bytes_tx_total` | `brix_io_bytes_read{proto="webdav"}` |
| `brix_webdav_bytes_rx_total` | `brix_io_bytes_written{proto="webdav"}` |
| `brix_s3_bytes_tx_total` | `brix_io_bytes_read{proto="s3"}` |
| `brix_s3_bytes_rx_total` | `brix_io_bytes_written{proto="s3"}` |
| `brix_io_latency_usec_bucket{le="<µs>"}` | `brix_io_latency_seconds_bucket{le="<s>"}` |
| `brix_cache_hits_total` | `brix_cache_requests_total{cache_status="HIT"}` |
| `brix_cache_misses_total` | `brix_cache_requests_total{cache_status="MISS"}` |

```promql
# throughput — before                     after
rate(brix_bytes_tx_total[5m])             rate(brix_io_bytes_read{proto="stream"}[5m])

# p99 latency — before (µs buckets)
histogram_quantile(0.99, rate(brix_io_latency_usec_bucket[5m]))
# after (seconds buckets; the result is now in seconds, so a panel unit that
# said "µs" must change to "s")
histogram_quantile(0.99, rate(brix_io_latency_seconds_bucket[5m]))

# cache hit ratio — before
sum(rate(brix_cache_hits_total[5m]))
  / (sum(rate(brix_cache_hits_total[5m])) + sum(rate(brix_cache_misses_total[5m])))
# after
sum(rate(brix_cache_requests_total{cache_status="HIT"}[5m]))
  / sum(rate(brix_cache_requests_total[5m]))
```

Two label-fidelity notes an operator must know before rewriting a query:

1. **`{port,auth}` is gone.** The eight byte counters were per-server-slot
   series carrying `port` and `auth` labels; `brix_io_bytes_*` carries only
   `proto`. A dashboard that broke throughput down per listener cannot be
   reproduced from the canonical family. This loss was decided in phase 110 W9
   (low-cardinality labels, invariant 8) and is not reopened here.
2. **`brix_bytes_*_total` vs `brix_bytes_root_*_total` collapse into one
   series.** Both folded into `brix_io_bytes_*{proto="stream"}`, so a query that
   subtracted one from the other to isolate non-root stream traffic has no
   canonical equivalent — that quantity is now always zero by construction.

### Facts verified before agreeing the replacements are lossless

- `brix_io_bytes_read{proto}` folds `shm->webdav.bytes_tx_total`,
  `shm->s3.bytes_tx_total` and `brix_unified_legacy_stream_bytes(shm, 0)` into
  the unified counter (`unified_export_io.c:unified_emit_io_bytes`), and
  `_written` folds the `rx` side. The deprecated families expose *exactly* those
  SHM fields, so nothing is lost by deleting the families.
- **The SHM counter fields stay.** `bytes_rx_total` / `bytes_tx_total` on the
  per-server slot, `shm->webdav.bytes_*` and `shm->s3.bytes_*` feed the
  canonical families above *and* the dashboard JSON (`api_snapshot.c`,
  `history.c`). This phase removes exposition, not accounting; there is no SHM
  ABI change and no rebuild-the-zone hazard.
- `brix_cache_requests_total{proto,cache_status}` renders the same three SHM
  fields as the pair it replaces — `unified.cache_hits` → `HIT`,
  `cache_misses` → `MISS`, `cache_neghits` → `NEGHIT` (`unified_export.c:
  unified_emit_cache`). The pair is strictly a projection of the canonical
  family.
- `$brix_cache_status` is already registered on the http plane and already
  probes the cvmfs, oci and rpm contexts (`http_variables.c:
  brix_request_cache_status`), so removing the per-plane variables removes
  registrations, not reachability of the fact.

## W1 — consumer census

Generated by matching all 22 deprecated spellings plus their `$`-prefixed and
JSON-quoted forms across the whole tree (`rg`, no path filter), then bucketing
by owner. 146 files matched; every one is classified below and no hit is
unclassified.

### In scope — the removal ledger

| Bucket | Files | Disposition |
|---|---|---|
| **Registrations (W2)** | `src/protocols/root/stream/stream_variables.c` (7 rows + 5 comment sites); `src/protocols/cvmfs/module.c` (2 rows); `src/protocols/oci/oci_module.c` (2); `src/protocols/rpm/rpm_module.c` (2) | delete the rows |
| **Prose naming a removed variable (W2)** | `src/core/http/http_variables.c` (the `cvmfs_cache_status()` byte-identical rationale), `src/protocols/cvmfs/{cvmfs.h,handler.c}`, `src/protocols/oci/{oci.h,oci_mirror.c}`, `src/protocols/rpm/{rpm.h,rpm_mirror.c}` | repoint at `$brix_cache_status` |
| **JSON emitter (W3)** | `src/observability/metrics/access_log.c` | drop 4 keys + their duplicated args + the pair-listing comment |
| **Metric emitters (W4)** | `unified_export_io.c` (usec block), `unified_export.c` (hits/misses), `stream_family.c` (4 of 8 rows), `webdav.c` (2), `s3.c` (2), `README.md`, `unified_record.c` (comment) | delete families / repoint prose |
| **Guards (W2/W4)** | `tools/ci/directive_registry_allowlist.txt` (7 phase-112 rows + 3 `*_cache` R7 rows), `tools/ci/check_metric_naming.py` (`DEPRECATED_METRICS` → empty), `tools/ci/check_metric_names.py` (comment) | delete entries |
| **Dashboards / alerts (W4)** | `contrib/grafana-dashboard.json` (3 latency exprs + hit-ratio), `contrib/prometheus-alerts.yml` (hit-ratio rule) | rewrite expressions |
| **Live test configs (W2)** | `tests/configs/nginx_lc_brix_stream_variables.conf`, `tests/configs/nginx_dyn_modules.conf` | rewrite `log_format` |
| **Tests (W2–W4)** | 30 under `tests/` (cachemx catalogue + 15 `test_cachemx_*`, the metrics-coverage trio, `test_metrics.py`, `test_large_file_metrics.py`, `test_{s3,webdav,gridftp}_metrics.py`, `test_aio_op_latency_metric.py`, `test_ci_guards.py`, `test_check_metric_naming.py`, `test_brix_stream_variables.py`), 8 mirrors under `k8s-tests/remote-suite/tests/`, `tests/cmdscripts/cvmfs_live_ext_part2.py`, `k8s-tests/remote-suite/tests/run_cvmfs_reverse.sh` | repoint at canonical names |
| **Operator docs (W5)** | 13 under `docs/` + `deploy/cvmfs/README.md`, `deploy/cvmfs/docker/README.md`, `deploy/cvmfs/docker/nginx.conf.in`, `deploy/rpm-mirror/brix.conf.example` | rewrite; the shipped `deploy/` configs are live config, not prose |

### Out of scope — classified, deliberately untouched

- **`"subject"` is overwhelmingly a different word.** 34 of the 40 `"subject"`
  hits are the OCI referrers subject descriptor
  (`src/protocols/oci/oci_referrers.{c,h}`, `shared/oci/gc_mark.c`), the token
  `sub` claim in the auth stack and BriXTest, a VOMS/GSI DN field, the
  ratelimit key parser, or a cvmfs attestation field. Only
  `access_log.c`'s `\"subject\"` is the deprecated JSON key.
- **`\"bytes\"` likewise.** `scan_record.c`, `scan_unittest.c`,
  `storascan_bench.c`, `xrd_doctor_json.c` and `dashboard/page.c` emit their own
  JSON documents with their own `bytes` key. Only `access_log.c` is in scope.
- **Historical phase docs keep their text.** `docs/refactor/phase-{56,68,85,87,
  104,106,108,110}-*.md`, `brix-rename-migration.md` and
  `testsuite-combinatorial-coverage-audit-2026-08-04.md` are the record of what
  those phases did. Rewriting them would falsify history; a reader who greps a
  removed name and lands in phase 110 finds the correct explanation.
- **Archives stay frozen.** `docs/_archive/`, `docs/superpowers/` and
  `tests/brix_suite/_legacy/_cachemx_catalog_{data,schema}_flat.py` are
  superseded snapshots kept for provenance. The `_legacy` catalogue files are
  not imported by the live suite (the live catalogue is
  `tests/brix_suite/cachemx/_cachemx_catalog_{data,schema}.py`), so editing them
  would create a false impression that they are maintained.
- **Hermetic guard fixtures keep their strings.** `tests/
  test_check_directive_registry.py` uses `cvmfs_cache` and `brix_session_dn` as
  *synthetic* names inside `tmp_path` fixtures with `BRIX_REGISTRY_ALLOWLIST`
  pointed at `/dev/null`; `tests/test_check_metric_naming.py` assigns its own
  `DEPRECATED_METRICS`. Both are independent of the real registry by
  construction and must stay that way — only their docstrings are refreshed.

## W2 — variable removal

### What was deleted

| Surface | Removed | What now carries the fact |
|---|---|---|
| `src/protocols/root/stream/stream_variables.c` | the 7 `$brix_session_*` rows | `$brix_dn`, `$brix_vo`, `$brix_sub`, `$brix_auth_method`, `$brix_tls`, `$brix_bytes_served`, `$brix_bytes_received` — same handlers, canonical names |
| `src/protocols/cvmfs/module.c` | `$cvmfs_cache`, `$brix_cvmfs_cache` **and their handler** `cvmfs_var_cache()` | `$brix_cache_status`, which reads the same `ctx->cache_status` through `brix_request_cache_status()` |
| `src/protocols/oci/oci_module.c` | `$oci_cache`, `$brix_oci_cache` + `oci_var_cache()` | `$brix_cache_status`; the finer disposition survives as `brix_oci_requests_total{outcome}` |
| `src/protocols/rpm/rpm_module.c` | `$rpm_cache`, `$brix_rpm_cache` + `rpm_var_cache()` | `$brix_cache_status`; `brix_rpm_requests_total{outcome}` |
| `tools/ci/directive_registry_allowlist.txt` | the 7 phase-112 `removal:` rows + the 3 `*_cache` R7 rows | — (R14's pin has nothing left to watch) |
| `tests/configs/nginx_lc_brix_stream_variables.conf`, `tests/configs/nginx_dyn_modules.conf` | the old spellings inside `log_format` | the canonical spellings; the log FIELD names (`auth=`, `out=`, …) are unchanged, so every existing assertion still parses |

The handlers went with the registrations. A dead `*_var_cache()` left behind
would be a second implementation of a disposition `$brix_cache_status` already
owns — exactly the duplication this phase exists to end. `ctx->cache_status`
itself stays: `cvmfs_var_origin()` and the per-plane metrics still read it.

### The removal is loud, not silent

nginx resolves variables at config-parse time, so a config still naming a
removed variable now aborts startup with `unknown "brix_session_dn" variable`
rather than logging `-` forever. That is the behavior the work item asks for and
it is asserted directly: `test_phase_112_removed_variable_is_now_unknown`
substitutes each of the seven removed names into the live fixture config, runs
`nginx -t` against the copy, and requires both a non-zero exit and nginx's own
diagnostic naming the variable.

### One fidelity loss, recorded

`$oci_cache` / `$rpm_cache` rendered five words (`hit`, `fill`, `local`,
`refused`, `error`); `$brix_cache_status` renders the cross-plane vocabulary, in
which `oci_rpm_cache_status()` maps `LOCAL` onto `HIT` and both `refused` and
`error` onto `-`. The distinction is not lost to the operator — it is a label
on `brix_oci_requests_total{surface,class,outcome}` and its RPM twin — but it is
no longer available *in a log line*. Both module headers now say so at the
point of removal.

## W3 — JSON removal

### The record before and after

Four facts were spelled twice in every `brix_access_json:` record. Phase 110
added the canonical key beside the old one; phase 112 deletes the old one and
its duplicated `printf` argument:

| Fact | Removed key | Canonical key |
|---|---|---|
| bytes moved by the op | `bytes` | `bytes_served` |
| backend service time | `latency_us` | `backend_time_us` |
| cache disposition | `from_cache` (a bare boolean) | `cache_status` (the shared HIT/MISS/`-` vocabulary) |
| authenticated subject | `subject` | `sub` |

`from_cache` is the only one that is not a rename: a boolean cannot express
`MISS` versus "no cache configured", which is why the canonical key carries the
same word `$brix_cache_status` and the Prometheus `cache_status=` label carry.

No schema, index template or stored query had to move with it. The census found
no ELK/OpenSearch mapping, no JSON-schema file and no dashboard query over the
access-log record in the tree; the only real parser is
`tests/test_brix_stream_variables.py::_brix_access_json`. The dashboard JSON in
`docs/05-operations/live-transfer-monitor.md` has its own `bytes` key on a
different surface (the live-transfer API, fed by the SHM counters that this
phase does not touch) and is deliberately unchanged.

### R15 — the pin that keeps the record single-spelled

R13 already required the canonical keys to be PRESENT. Nothing required the
superseded ones to be ABSENT, so a later edit could quietly reintroduce a
second spelling. `tools/ci/directive_registry_w5.py` grows **R15**, built on
the same self-deleting-pin machinery as R14: dormant while
`docs/refactor/phase-112-*.md` is unwritten or `PLANNED` — it can never shorten
a deprecation window it does not own — and permanent once the doc is
`IMPLEMENTED`, reporting one finding per deprecated key still found in
`access_log.c`. The keys are matched as they appear in the C format string
(`\"bytes\":` with the colon), so `\"bytes\":` cannot match inside
`\"bytes_served\":`.

### Acceptance

`test_phase_112_access_json_carries_each_fact_exactly_once` reads EVERY record
the fixture node emitted, not just the last, and requires each canonical key
present and each removed key absent. The op shapes the acceptance criteria name
fall out of that automatically — the dirlist record it asserts over is itself a
zero-byte (`"bytes_served":0`), unauthenticated (`"auth_method":"none"`),
no-cache (`"cache_status":"-"`) record. R15's own four tests cover the guard
from both sides of its trigger, including that the canonical record trips
nothing.

## W4 — metric removal

### Eleven families, three canonical replacements

| Removed family | Canonical replacement |
|---|---|
| `brix_io_latency_usec` (+`_bucket`/`_sum`/`_count`) | `brix_io_latency_seconds{proto,op}` |
| `brix_webdav_bytes_tx_total`, `brix_s3_bytes_tx_total`, `brix_bytes_tx_total`, `brix_bytes_root_tx_total` | `brix_io_bytes_read{proto}` |
| `brix_webdav_bytes_rx_total`, `brix_s3_bytes_rx_total`, `brix_bytes_rx_total`, `brix_bytes_root_rx_total` | `brix_io_bytes_written{proto}` |
| `brix_cache_hits_total{proto}`, `brix_cache_misses_total{proto}` | `brix_cache_requests_total{proto,cache_status}` |

The byte direction is not a transcription slip. `brix_io_bytes_read` is named
from the *client's* perspective — a client read is a server transmit — so the
`tx` counters fold into `_read` and the `rx` counters into `_written`
(`unified_export_io.c`). Getting this backwards would have swapped every byte
assertion in the suite while leaving the totals plausible, which is exactly the
kind of error a rename sweep introduces silently.

### The fold was proved before a single assertion moved

A removal is only safe if the surviving family already carries the same number.
Four facts were established from the source, not assumed:

1. **Magnitude.** Per protocol the canonical value is
   `unified.io_bytes_*[proto]` **plus** a fold: ROOT ←
   `brix_unified_legacy_stream_bytes()`, WEBDAV ← `shm->webdav.bytes_{tx,rx}_total`,
   S3 ← `shm->s3.bytes_{tx,rx}_total`. The removed families read those very SHM
   words, so the canonical family already reported the identical byte count.
2. **No double counting.** `brix_metric_op_done()` has **four** callsites, not
   the three a protocol-side grep shows. Three are protocol emitters
   (`s3/metrics.c`, `webdav/metrics.c`, `gridftp/ev/ftp_ev_metrics.c`) and the
   first two pass `bytes = 0`. The fourth is the VFS post-op observer
   (`fs/vfs/vfs_observe_internal.h`, `brix_vfs_observe_ctx_op_ex`), which
   *does* pass real bytes — and is the one that had to be checked, because a
   byte it books lands in `unified.io_bytes_*[proto]` on top of the export-time
   fold. It is byte-neutral for the data planes for two independent reasons:
   the data path never reaches it (`vfs_read.c` and `vfs_write.c` contain no
   observe call at all — a served byte is zero-copy and is booked once, at the
   plane's serve site), and the three staged-commit observations opt out
   explicitly with `meter_io = 0` because the owning protocol books those bytes
   itself. `unified.io_bytes_*[proto]` is therefore zero for webdav, s3 and
   stream, and the fold supplies the whole value rather than a second copy of
   part of it. All three conditions are load-bearing and are pinned by
   `test_op_done_has_four_callsites_not_three`,
   `test_http_emitters_pass_no_bytes_to_op_done`,
   `test_staged_commit_opts_out_of_io_metering` and
   `test_the_data_path_never_reaches_the_vfs_observer`.
3. **Aggregation level.** The removed webdav/s3 scalars were instance-wide —
   the same scope as `brix_io_bytes_*{proto}` — so `== size` assertions stay
   *exact* rather than becoming `>=`.
4. **Identity of the root pair.** `brix_bytes_tx_total` and
   `brix_bytes_root_tx_total` were never two facts: `disconnect_report.c` adds
   the same `ctx->totals.bytes` (payload, not framing) to both. Only their
   removal makes that visible; nothing is lost by deleting one of two names for
   one number.

Framing bytes remain separately available: `brix_wire_bytes_{rx,tx}_total`
is a different measurement and is **kept**.

### The unit change is a real change, not a rename

`brix_io_latency_seconds_sum` prints `%.6f` seconds (`sum_usec / 1000000.0`)
and each `_bucket` `le` is a `%.6f` second boundary. `_count` is unchanged.
Any recording rule or alert that divided a `_sum` by a `_count` and compared
against a microsecond threshold is now wrong by 10⁶ — which is why this is the
one item in the phase that appears under *Breaking* with an explicit sentence
in the release note rather than only in a table row.

### What is deliberately KEPT

Twelve ipv4/ipv6 twins — the full cross-product of
`brix_{webdav,s3,}_bytes_{rx,tx}_{ipv4,ipv6}_total` — look like members of
the removed set
and are not: the unified families carry no IP-version label, so deleting them
would delete a fact rather than a spelling. `brix_wire_bytes_*`,
`brix_cache_bytes_evicted_total`, `brix_cvmfs_bytes_served`,
`brix_storage_io_bytes_*`, `brix_vo_bytes_*` and `brix_tpc_bytes_total` are
complementary measurements, not duplicates, and are untouched.

### The one fidelity loss, recorded

The removed stream byte families were keyed by `{port,auth}` — a per-listener,
per-security-plane split. `brix_io_bytes_*{proto="stream"}` sums every server
slot. That breakdown is genuinely gone from the exposition; the per-`{port,auth}`
*request* and *wire* ledgers (`brix_requests_total`,
`brix_wire_bytes_{rx,tx}_total`) still carry it, so an operator can still
attribute traffic to a listener, just not payload bytes specifically. The
cachemx suite tolerates the loss because `xdist_group("lc-cachemx")` serializes
its drivers: plane attribution comes from which driver ran, not from a label.

### The cache vocabulary replaces two families with one label

`brix_cache_requests_total{proto,cache_status}` states the disposition as a
label value drawn from the one cross-plane vocabulary
(`brix_metric_cache_status_name()`: `HIT`, `MISS`, `BYPASS`, `NEGHIT`, `-`) —
the same word `$brix_cache_status` logs and the JSON `cache_status` key prints.
`BYPASS` emits no series, which is honest: absent is not zero.

Two suite checks got *stricter* rather than weaker as a result.
`test_manager_holds_no_cache_counters` now walks every row of the one family
and requires each to be zero, so it covers the `NEGHIT` rows that had no
counterpart family and went unexamined before; `test_cachemx_ownership`'s
stillness checks now tag by `proto` alone, summing every disposition instead of
hits alone.

### Consumers migrated with the source

- `contrib/grafana-dashboard.json`: the latency panel's three
  `histogram_quantile` expressions move to `brix_io_latency_seconds_bucket` and
  the panel unit becomes `s`; the cache-hit-ratio panel becomes
  `HIT / clamp_min(HIT|MISS, 1)` over the one family.
- `contrib/prometheus-alerts.yml`: `XrootdCacheMissSurge` uses the same ratio.
  `clamp_min` keeps a quiet server from alerting on 0/0.
- `src/observability/metrics/README.md` and the eleven `# HELP`/`# TYPE`
  blocks: the deprecation notes are deleted rather than reworded, because a
  note saying "kept for one release" is itself a compatibility surface.
- The calibrated cachemx catalogue drops from 228 families to 220 (−11
  removed, +3 arriving from phases 110 and 108), with `HELP` and `LABEL_KEYS`
  kept key-identical and `CONDITIONAL` re-derived.

### The guards after the deletion

`DEPRECATED_METRICS` in `tools/ci/check_metric_naming.py` is now **empty**, and
deliberately kept rather than deleted: it is the registry that made the
`brix_cache_{hits,misses}_total` escape visible in W1, and an empty registry is
the correct steady state — `M2` still fires the moment a family is registered
deprecated and outlives its phase. `M1` is what now holds the line on the unit:
a new `_usec` latency histogram with no registry entry is a finding on sight.

`test_ci_guards.py` pins the extractor against the real C, and its latency row
became three rows (`_bucket` `{proto,op,le}`, `_count` `{proto,op}`, bare
`{proto,op}`) — a stricter pin than the single `_usec` row it replaced.

## W5 — documentation

### One migration table, in the release note

`CHANGELOG.md` under *Unreleased → Breaking* carries the single old-to-new
table for all three surfaces (variables, JSON keys, metric families) plus the
seconds-vs-microseconds sentence. Every other copy is deleted rather than
updated:

- `docs/03-configuration/config-reference.md` had a second, drifting copy of
  the same table under *Deprecated names*. It is replaced by the four aliases
  that genuinely still resolve (`$cvmfs_class`, `$cvmfs_origin`, `$oci_class`,
  `$rpm_class`) and a pointer to the release note for everything removed. The
  sentence promising that "both spellings are emitted during the deprecation
  window" is deleted — it is now false, and a false reassurance in a reference
  is worse than no sentence.
- The plane-variable table loses `$brix_cvmfs_cache`, `$brix_oci_cache` and
  `$brix_rpm_cache`; the alias row's count drops from seven names to four.

### The shipped configs were the urgent half

A stale `log_format` is a **startup abort**, not a silent empty field, so any
config in the tree still naming `$cvmfs_cache` would have failed `nginx -t` the
moment W2 landed. Three shipped artifacts and one live test fixture were in
that state and now use `$brix_cache_status`:

`deploy/cvmfs/docker/nginx.conf.in`, `deploy/cvmfs/README.md`,
`deploy/rpm-mirror/brix.conf.example` (comment) and
`k8s-tests/remote-suite/tests/run_cvmfs_reverse.sh`.

### Vocabulary changes stated where the operator reads them

The plane-local disposition words were not identical to the cross-plane ones,
so each protocol document says what the mapping is at the point of use rather
than leaving the reader to infer it:

| Plane | Old spelling | Reads now |
|---|---|---|
| cvmfs | `hit` / `fill` / `neg` | `HIT` / `MISS` / `NEGHIT` |
| oci, rpm | `hit` / `fill` / `local` | `HIT` / `MISS` / `HIT` |
| oci, rpm | `refused` / `error` | `-` — not cache dispositions; read them off the `outcome` label of `brix_{oci,rpm}_requests_total` |

Documented in `docs/04-protocols/cvmfs.md`, `docs/04-protocols/rpm.md` and
`docs/05-operations/oci-mirror.md`. `docs/04-protocols/cvmfs.md` also claimed a
`stale` value that no enum ever had (`cvmfs.h` defines only
`NONE`/`HIT`/`FILL`/`NEG`); it goes with the rest of the removed vocabulary.

### Deliberately unchanged

`docs/05-operations/live-transfer-monitor.md` has its own `bytes_rx_total` /
`bytes_tx_total` JSON keys on the live-transfer API — a different surface fed by
the SHM counters this phase does not touch. `docs/10-reference/nginx-internals.md`,
`docs/08-metrics-monitoring/metrics-bug-patterns.md` and the developer-guide
plans name the same words as **C struct fields**, which still exist and still
feed the fold. `docs/doxygen/html/` is generated, untracked and gitignored.
Historical records — `docs/refactor/phase-{56,108,110}-*.md`,
`brix-rename-migration.md`, the `_archive/` and `superpowers/` trees and the
`history-*.md` topic docs — say what was true when written and are left alone.

## W6 — close

Status flips to `IMPLEMENTED` in this document, which arms both self-deleting
pins at once: `R14`/`R15` in `tools/ci/directive_registry_w5.py` and `M2` in
`tools/ci/check_metric_naming.py` all key off
`docs/refactor/phase-112-*.md` saying `**Status:** IMPLEMENTED`. Green after
the flip:

- `tools/ci/check_metric_naming.py --fail` — 100 typed families, 0
  deprecated-registered, no findings;
- `tools/ci/check_metric_names.py --fail` — every `brix_*` family cited in any
  document exists in the exposition, 0 grandfathered;
- `tools/ci/check_directive_registry.py --fail` — 693 registrations, 564 unique
  names, no drift. R15 joins the gating set here (R3 and R8 keep their
  docs-from-source advisory posture, unchanged by this phase).

Arming the M2 pin exposed that the guard carrying it could not run in CI at
all: `tools/ci/check_metric_naming.py` shipped without its mode bit (guards.yml
invokes guards as bare paths, so it would have died on `Permission denied`) and
was never referenced by `.github/workflows/guards.yml` in the first place —
`tools/ci/guard_set.py --explain` called it *advisory only*, and
`tests/test_ci_guards.py` proves both halves of that failure mode. Both are
fixed here: the script is executable, and guards.yml runs it as
`check_metric_naming.py --fail` beside `check_metric_names.py` (50 ms, so it
also joins the pre-push set). A self-deleting pin that CI never executes is a
comment, and phase 112's whole deprecation-window contract rests on this one.

### The trigger is anchored — a doc that explains the pin must not arm it

Verified after the flip, and fixed here: the trigger regex was unanchored, so
it matched a phase document that merely **quotes** `**Status:**` + `IMPLEMENTED`
while explaining the mechanism. The opening paragraph of this W6 section does
exactly that, which is how it was found — this document matched its own trigger
twice, once as a status heading and once as prose. Unanchored, any future phase
doc that documents this machinery arms it from its first `PLANNED` draft: R14,
R15 and M2 would all fire on the very commit that *opens* a deprecation window,
demanding the removal of a surface deprecated seconds earlier, and the author's
only route out is to stop writing down how the pin works.

Both copies of `_IMPLEMENTED_RE` — `directive_registry_w5.py` and
`check_metric_naming.py`, written out by hand, importing nothing from each
other — are now `^\*\*Status:\*\*\s*IMPLEMENTED` with `MULTILINE`. A status
heading opens its line; a quoted mention is indented or mid-sentence. Re-run
across all 125 `docs/refactor/*.md` before and after: **zero** documents change
verdict, so the tightening is behaviour-preserving today and closes the hole
for the next phase. Two consequences worth keeping in mind when editing this
file: do not reflow a quoted trigger — in W6's opening paragraph or in this one
— so that it lands at the start of a line, and do not "simplify" one copy of
the regex without the other
— `test_both_guards_spell_the_implemented_trigger_identically` fails loudly if
they drift, which is the only reason the asymmetry is survivable.

A repository-wide search for the eleven families and the eleven variables
returns only: the release-note table, the historical phase documents, one
explanatory comment at the point of removal in `unified_export_io.c`, the
deliberate absence assertion in `test_cachemx_exposition.py`, and the hermetic
synthetic fixture in `test_check_metric_naming.py` that exercises M2 from both
sides of its trigger.

## Tests and acceptance

- success: canonical variables resolve on HTTP and stream; canonical JSON and
  metric families contain the Phase-110 values;
- error: an nginx config using each removed variable is rejected or the
  documented nginx unknown-variable behavior is asserted — the seven stream
  aliases in `tests/test_brix_stream_variables.py`, the six HTTP cache
  variables in `tests/test_phase112_consumer_surface_closure.py`;
- security/operations negative: no old field or metric is emitted, including on
  auth failures, cache negative hits and zero-byte requests;
- guards: `check_directive_registry.py --fail` and
  `check_metric_naming.py --fail` pass after the status flip, and both pins are
  driven from *both* sides of their trigger by
  `tests/test_phase112_deprecation_contract_closure.py`, since after this phase
  R14 and M2 pass over empty registries; the shipped operator artifacts under
  `contrib/` are held by `tests/test_phase112_consumer_surface_closure.py`,
  which no guard covers because a stale PromQL query is not an error;
- repository search: every deprecated spelling has zero live-code/config/query
  consumers, excluding the release-note migration table and negative fixtures.

### Every discovery is an assertion

The removals above are asserted by the existing suite. What the *work* found —
the facts that were true only by accident until they were checked — is pinned
by `tests/test_phase112_compatibility_closure.py`, twenty-five cases in three
groups:

- **compatibility.** No tracked config or `log_format` names a brix-owned
  variable the modules do not register. This is the class the removal created:
  nginx resolves variables at config-parse time, so a shipped artifact still
  naming `$cvmfs_cache` does not degrade to `-`, it *refuses to start*. The
  sweep found four such artifacts and no test would have caught any of them.
  The scanner excuses a name only if it is registered, minted by the same file
  (`map`/`geo`/`split_clients`/`set`), or accompanied by an
  `unknown "<name>" variable` expectation — a deliberate negative fixture — and
  two cases prove it is neither vacuous nor over-excusing. That scan skips
  `docs/` on purpose, so a second case closes the gap it leaves: the copy-paste
  source an operator actually migrates from is the fenced `log_format` in a
  *current* operator doc, and a removed name there is the same startup abort a
  shipped config would be. The doc-fence scan covers exactly the executable part
  of the operator docs — leaving the frozen refactor/archive tree and the
  CHANGELOG migration table their historical spellings — and its own fixture
  proves it fires on a fenced example while ignoring the same name in prose.
- **feature.** The per-plane cache maps are total over their source enums; the
  byte fold is client-perspective and cannot double-count (the four-callsite
  proof above, all three conditions); latency is seconds-only; and the twelve
  ipv4/ipv6 twins that merely *look* like members of the removed set are still
  emitted, so a later pattern-matching sweep cannot take them with it.
- **security / operations.** No removed alias or orphaned `*_var_cache()`
  handler survives to become a second, driftable implementation of an identity
  fact `$brix_dn`/`$brix_sub` owns; the `{port,auth}` attribution that makes
  the recorded byte-fidelity loss acceptable is still on the request and wire
  ledgers; and the guard carrying the M2 pin is invoked *with `--fail`*, since
  a wired guard that exits 0 is not a pin. The cull's *positive boundary* is
  pinned too: it deleted only the `$*_cache` variables and their `*_var_cache`
  handlers, so the `$*_class`/`$*_origin` aliases in those same three module
  files — `cvmfs_var_class` sits two `ngx_string` rows below the deleted
  `cvmfs_var_cache` — must survive, under both spellings and with their
  handlers intact; every removal assertion checks only that the cache names are
  *gone*, so a sweep taking a neighbouring `*_var_class` with them would stay
  green while deleting a fact. That boundary is also cross-checked against
  `config-reference.md`: the four aliases its *Deprecated names* section
  promises "still resolve" must be exactly the survivors and each must actually
  register, or the reference is a false promise nginx aborts a `log_format` on.

One further compatibility fact is pinned there because it is a split, not a
removal: phase 112 took the plane-local disposition out of the **access** log,
but left `handler_finalize.c`'s `cvmfs-trace:` **error**-log line spelling it
`hit`/`fill`/`neg` — and two live consumers
(`run_cvmfs_upstream_metrics.sh`, `cvmfs_live_ext_part3.py`) still grep exactly
that. "Finishing" the rename in the C trace breaks them; an access-log consumer
regressing to lowercase silently never matches again. The test requires the
trace to keep its own vocabulary and every other consumer to have left it.

### Second wave — the deprecation-window contract itself

Those twenty-one cases pin the *surfaces*. A re-verification pass found that
nothing pinned the machinery the phase leaves behind for the next removal —
the part this phase, by succeeding, emptied. Nine further cases in
`tests/test_phase112_deprecation_contract_closure.py`; every one was
mutation-checked against a copied tree (twelve mutants, each killed by exactly
the intended assertion, none by a neighbour):

- **compatibility — the trigger.** All three pins decide whether to wake by
  running a regex over English prose. The live doc must trip both guards; the
  spellings that survive a reformat (whitespace, a line break, letter case) and
  those that silently disarm every pin at once (`**Status**: IMPLEMENTED`, a
  status table cell, an unbolded label, a mid-line mention) are enumerated, so
  anyone normalising the heading is told to move the two regexes with it.
- **compatibility — two hand-written copies.** `_IMPLEMENTED_RE` exists twice
  and the guards never import each other; pattern and flags must match
  character for character. This is the drift class phase 107 hit with its two
  mutation-label tables, and it fails asymmetrically: one pin keeps firing,
  which reads as "the other guard is broken" rather than as drift.
- **security — a doc that only quotes the trigger stays dormant.** The
  anchoring fix above, pinned from both sides: a `PLANNED` doc containing a
  quoted `**Status:** IMPLEMENTED` must not arm the pins, and a real status
  heading must still arm them.
- **security — anti-vacuity, twice.** Phase 112 emptied both removal
  registries: the allowlist has no `removal:` row left and `DEPRECATED_METRICS`
  is `{}`. R14 and M2 now pass over nothing, which in a CI log is
  indistinguishable from passing correctly. R14 is therefore driven directly
  from three sides (overdue → reported; window still open → silent; alias
  already unregistered → silent), and R15 — the one pin with a non-empty
  registry, and so the only one that can still fail a build — is driven against
  a planted emitter that re-adds `from_cache`.
- **compatibility — R15 matches key position, not a word.** `bytes` is a prefix
  of its replacement `bytes_served`, and `sub` is a prefix of the `subject` it
  replaces, so the registry stores each key with its escaped quotes and colon.
  Rewritten as bare words the rule fires forever on the *correct* record, which
  reads as "the removal did not take" and invites putting the key back.
- **feature — all eleven families, not one.** Only `brix_io_latency_usec` was
  pinned absent; the other ten were verified once by hand. The check runs
  against what the exporter *declares* — HELP lines plus quoted name literals —
  because eight of the eleven were emitted through `SRV_COUNTER_HDR` macros
  that assemble their HELP line at compile time, and a family invisible to a
  `# HELP` grep still lands in a scrape. The four canonical replacements are
  asserted present in the same case, since a removed family whose replacement
  is also missing is a deleted fact.
- **compatibility — no `DEPRECATED` notice survives in the exposition.** The
  Group B counters shipped with `# DEPRECATED` in their HELP text. That notice
  is itself a compatibility surface: served to every scraper, naming the dead
  family, and apt to outlive the series if a header string is kept "for the
  note".
- **compatibility — the release note carries the migration.** The Group C
  deviation was accepted on the stated grounds that the obligation it creates
  is editorial rather than technical, i.e. discharged by the CHANGELOG and by
  nothing else — and the editorial half is precisely the half that can quietly
  not happen. The `### Breaking` block under `## Unreleased` must exist, name
  each removed surface class beside its replacement, and state the seconds unit
  change; a recording rule ported by name alone is wrong by 10⁶.

### Third wave — the two surfaces a consumer touches

The first two waves both look inward: at the tree that produces the names, and
at the machinery this phase leaves behind. Neither looks at the places the
removal is actually *felt*, and those two places fail in opposite directions.
Eight further cases in `tests/test_phase112_consumer_surface_closure.py`, each
mutation-checked against a copied tree (eleven mutants, all killed):

- **feature — the acceptance criterion, on the plane where it bites.** W2's
  acceptance asks that "an nginx config using each removed variable is
  rejected". That was pinned for the seven `$brix_session_*` stream aliases
  (`test_brix_stream_variables.py`, live fleet) and for *nothing else* — the six
  removed cache variables, the ones that live on the HTTP plane, had no
  assertion at all. The HTTP plane is the loud half: nginx does not log a `-`
  for an unknown variable, it refuses the configuration at parse time, so an
  operator whose `log_format` still names `$cvmfs_cache` does not lose a log
  field, the server does not start. Six rejection cases plus a success case for
  `$brix_cache_status`, run through the shared `config_parse.nginx_t` helper and
  the reviewable template `tests/configs/nginx_phase112_http_var.conf` — pure
  `nginx -t`, no fleet, no registry.
- **security — a stale PromQL rule is a detector that cannot fire.** The
  opposite failure mode, and the reason the shipped artifacts needed a pin of
  their own: PromQL naming a family nobody exports is not an error. It returns
  an empty vector, silently, forever. `XrootdCacheMissSurge` still asking for
  `brix_cache_hits_total` would report healthy *because* it is blind, and every
  green build would agree. `contrib/prometheus-alerts.yml` and
  `contrib/grafana-dashboard.json` were migrated by hand during W4 and verified
  by eye; nothing held them there afterwards. Both are now pinned clean of all
  eleven removed families.
- **feature — removal is not migration.** Deleting the stale queries satisfies
  the two cases above and leaves the operator with no panel at all, which is why
  the dashboard is separately required to *query* each of the four canonical
  replacements. A migration that only deletes is a regression wearing a green
  build.
- **compatibility — the cache pair became a label, not two families.** A
  consumer who "migrates" `brix_cache_hits_total` / `_misses_total` by renaming
  produces a rule that parses and is wrong: the ratio silently becomes 1. The
  shipped rule must name `brix_cache_requests_total` *and* select on
  `cache_status`.
- **compatibility — the seconds/µs hazard, as a pin rather than a warning.**
  §W4's unit note ("a real change, not a rename") had no assertion behind it. A
  panel unit or a `/ 1000000` divisor carried across unchanged stays perfectly
  valid PromQL and is wrong by a factor of a million. Every panel plotting
  `brix_io_latency_seconds` must declare unit `s` and carry no µs-era scaling;
  the case also asserts at least one such panel exists, so the pin cannot go
  vacuous by the dashboard dropping latency altogether.
- **security — the census escape, generalised to a shape.**
  `brix_cache_hits_total` reached this phase without ever entering
  `DEPRECATED_METRICS`; the phase learned to distrust name-by-name inventories
  but never wrote that lesson down as a check. The generalisation is the
  *shape* — a byte counter that bakes its plane into the family name. It cannot
  be banned outright: four live families share the shape legitimately because
  they carry the dimension as a label (`brix_vo_bytes_{rx,tx}_total`,
  `brix_wire_bytes_{rx,tx}_total`). The census is therefore pinned exactly, both
  directions — a new per-plane counter cannot appear, and a later "clean up the
  shape" sweep cannot take the four labelled survivors with it.

## Non-goals

- no new canonical names;
- no label-cardinality expansion;
- no removal before the release window;
- no compatibility aliases hidden in dashboards or exporters after source-side
  deletion.
