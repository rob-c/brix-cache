# SSI Phase 6 — Config, metrics, conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SSI framework operable and observable — config directives to enable services and tune caps, low-cardinality metrics, and a conformance pass that pins wire-compat — then declare the framework + CTA service done.

**Architecture:** Config directives follow the module's directive recipe (field in `src/types/config.h` → `ngx_command_t` in the stream module directives → merge). Metrics use the existing `XROOTD_*_METRIC_INC` machinery with low-cardinality labels. Conformance runs the real `libXrdSsi` client (`tests/ssi_client.cc`) for the generic framework and golden CTA vectors for the protobuf contract.

**Tech Stack:** C (nginx stream config + metrics), pytest, real `libXrdSsi` client.

## Global Constraints

- NO `goto`; functional + modular; no new globals.
- **Metric labels low-cardinality only** — no paths, reqIds, archive-ids, or usernames as labels (INVARIANT 8). Service/op/status are bounded enums.
- Config merge respects `NGX_CONF_UNSET`; main→srv→loc precedence; defaults documented.
- New directives need no `./configure` unless a new top-level block is added (none here) — they register in the existing stream module command table.
- 3 tests per change: directive parsed/applied + bad value rejected + metric increments observed.

## Consumed interfaces

- Phase 1–5 SSI engine; `xrootd_ssi_max_inflight` cap (Phase 1), provider registry, CTA service + journal.
- Existing config plumbing: `src/types/config.h` (`ngx_stream_xrootd_srv_conf_t`), the stream module directive table (`grep -rn "ngx_command_t" src/stream/`), metrics enums (`src/metrics/metrics_internal.h`) + `XROOTD_*_METRIC_INC`.

---

### Task 1: Config directives

**Files:**
- Modify: `src/types/config.h` (add fields)
- Modify: the stream module directive table + merge (`src/stream/module*.c` — `grep` for the existing `xrootd_ssi` directive added in Phase 1)
- Modify: `src/ssi/*` to read the configured values (cap, enabled services)
- Test: `tests/test_ssi_config.py`

**Directives (all default-off / sensible defaults):**
- `xrootd_ssi on|off` (exists)
- `xrootd_ssi_service <name> [args...]` — enable a provider (e.g. `cta`); without it only test services resolve.
- `xrootd_ssi_max_inflight <n>` (default `XROOTD_SSI_MAX_INFLIGHT`=8)
- `xrootd_ssi_request_max <size>` / `xrootd_ssi_response_max <size>` (defaults 1 MiB)
- `xrootd_ssi_cta_journal <path>` / `xrootd_ssi_cta_executor test|prod` (default `test`)

- [ ] **Step 1: Failing test** — `test_ssi_config.py`: a config with `xrootd_ssi_service cta;` + `xrootd_ssi_max_inflight 4;` starts and `/.ssi/cta` resolves; a config with `xrootd_ssi_max_inflight 0;` is rejected by `nginx -t`; with `cta` not listed, `/.ssi/cta` open → `kXR_NotFound`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the fields (`NGX_CONF_UNSET`/`NGX_CONF_UNSET_UINT`), command handlers, merges, and have the provider registry consult the enabled-services list (so `cta` is gated by `xrootd_ssi_service cta;`). Make `xrootd_ssi_session_req`'s cap read the configured `max_inflight`.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 2: Metrics

**Files:**
- Modify: `src/metrics/metrics_internal.h` (enum slots) + the relevant `src/metrics/*.c` export
- Modify: `src/ssi/ssi.c` / `deliver.c` / `svc_cta/cta_service.c` (increment at callsites)
- Test: `tests/test_ssi_metrics.py`

**Metrics (low-cardinality):**
- `xrootd_ssi_requests_total{service,op,status}` — `service`∈{echo,…,cta}, `op`∈{archive,retrieve,cancel,query,other}, `status`∈{ok,error,canceled}
- `xrootd_ssi_inflight` gauge
- `xrootd_ssi_alerts_pushed_total`
- `xrootd_ssi_attn_push_failures_total`

- [ ] **Step 1: Failing test** — submit some requests; scrape `/metrics`; assert `xrootd_ssi_requests_total` increments with bounded label sets and that no label value contains a path/reqId/username.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** via `XROOTD_*_METRIC_INC` at submit/deliver/terminal callsites; map op/status to the bounded enums (never raw strings from the wire).
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 3: Conformance pass + final regression

**Files:**
- Modify: `tests/ssi_client.cc` if needed to exercise async/streaming/multiplex via the real client
- Create: `tests/test_ssi_conformance.py` (aggregator) — or extend `test_ssi_wire.py::TestSsiRealClient`

- [ ] **Step 1:** Extend the real `libXrdSsi` client tests to cover: async response (deferred), streamed response, an alert round-trip, and 2-way multiplex — the generic framework's gold-standard proof. Where the stock client cannot drive a case, fall back to the golden-vector raw-wire proof and document the limitation inline.
- [ ] **Step 2:** Full SSI regression: run every `tests/test_ssi*.py` + all `src/ssi/**/*_unittest.c` standalone tests; record pass counts.
- [ ] **Step 3:** Run a broad module smoke (`pytest tests/ -k "ssi or conformance" -v --tb=short`) to confirm no cross-subsystem regression. Commit.

---

### Task 4: Final docs

- [ ] Update `src/ssi/README.md` + `src/ssi/svc_cta/README.md`: full directive reference, metric reference, the conformance story (real client + golden vectors) and its honest limitation (no standalone `xrdssi` CLI). Update the design spec's status to *implemented*. Commit.

---

## Self-Review

- Directives (1), metrics (2), conformance (3), docs (4) cover the spec's §7 (config/observability) + §8 (testing) closure.
- Metric cardinality invariant enforced + explicitly tested (Task 2). ✓
- Conformance honesty (real client where possible, golden vectors otherwise) preserved from the spec (Task 3). ✓
- No new top-level config block → no `./configure` needed for directives (only when files were added in earlier phases). ✓
- No TBDs; the directive/metric names are concrete; the only "grep for the existing table" steps are exact-location lookups, not undefined work.

## Execution Handoff

Phase 6 of 6 — final. Depends on Phases 1–5. On completion the full XrdSsi framework + CTA-protobuf tape service is shipped, operable, observable, and conformance-pinned.
