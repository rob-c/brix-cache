# Archived documentation

Superseded planning and status documents kept for historical reference only.
**Do not treat anything here as describing current code** — the source under
`src/` is the authoritative implementation, and the live docs live under the
numbered `docs/NN-*` sections.

This archive was consolidated on **2026-06-13** (documentation reorganisation
pass): completed implementation plans, point-in-time status reports, superseded
design proposals, and one-off audits were moved here from the active tree so the
live documentation only contains material that describes current behaviour.

---

## Early refactoring / consolidation reports

| Document | Why archived |
|---|---|
| `refactoring-proposal.md` | Early refactoring proposal; superseded by the `docs/refactor/phase-*.md` series. |
| `PHASE_2_SUMMARY.md`, `PHASE_2_COMPLETE.md`, `PHASE_2_FINAL_REPORT.md`, `CODE_CONSOLIDATION_IMPLEMENTATION.md` | Reports of an early "Phase 2 / Code Consolidation" effort (2026-06-05) that introduced `src/core/config/conf_helpers.h` and `src/core/compat/alloc_helpers.h`. Both files were later removed — the config-merge consolidation was redone via **Option A** in [`../refactor/phase-5-config-consolidation.md`](../refactor/phase-5-config-consolidation.md) (nginx built-ins + `src/core/config/merge_macros.h`). These reports reference infrastructure that no longer exists. |

## Point-in-time snapshots & audits

| Document | Why archived |
|---|---|
| `CHANGES_VS_GITHUB-20260512.md` | "Changes vs origin/main" diff snapshot dated 12 May 2026; long superseded by committed history. |
| `CODE_REDUCTION_ANALYSIS-refactor-candidates.md` | Grounded 1.2–1.5k LoC reduction analysis (boilerplate consolidation candidates); a proposal, not implemented as written. |
| `CODE_REDUCTION_ANALYSIS-70pct-frontier-proposal.md` | Speculative "70% intent-centric rewrite" blueprint; aspirational, never pursued. |
| `IMPLEMENTATION_PLAN-audit.md` | "Implementation plan audit" of once-missing features that have since been implemented. |
| `comprehensive-testing-roadmap.md` | Completed/superseded testing roadmap; current testing docs are `docs/09-developer-guide/testing-*`. |
| `failing-tests-investigation-2026-05-19.md` | Point-in-time failing-tests triage (2026-05-19). |
| `changelog-local-archive.md` | Local changelog snapshot. |
| `removing-mock-components.md` | Completed "remove mock components" task notes. |

## Identity / VFS / TPC / metrics unification family (`unification/`)

Completed implementation plans for the unification work that landed in the
"identity unification, Kerberos auth, TPC registry, S3 hardening, cache metadata"
release (commit `e87c1ca`). The code is the source of truth; these are the plans.

| Document | Subject |
|---|---|
| `unification/PHASE1_RESOLVER_IMPLEMENTATION.md` | Shared path-resolver |
| `unification/PHASE2_IDENTITY_ABSTRACTION.md` | `xrootd_identity_t` abstraction |
| `unification/PHASE3_VFS_OPERATIONS.md` | VFS operations layer (`src/fs/`) |
| `unification/PHASE4_CACHE_UNIFICATION.md` | Cache open/fill unification |
| `unification/PHASE5_TPC_UNIFICATION.md` | TPC unification |
| `unification/PHASE6_METRICS_OBSERVABILITY.md` | Metrics / observability unification |
| `UNIFICATION_STRATEGY_2026-06-05.md`, `UNIFICATION_IMPLEMENTATION_STATUS_2026-06-05.md` | Strategy + status overview for the above |

## Completed developer-guide plans

| Document | Why archived |
|---|---|
| `dashboard-feature-implementation-plan.md` | HTTPS dashboard roadmap — implemented (`src/observability/dashboard/`). |
| `dedicated-test-servers-plan.md`, `plan-dual-stack-transfer-testing.md`, `plan-fd-stat-cache-migration-complete.md`, `no-mock-infrastructure-plan.md`, `mandatory-thread-webdav-plan.md`, `tier1-implementation-plan.md`, `missing-tests.md` | Completed implementation / test plans; the work is in `src/` and `tests/`. |
| `shared-code-plan-v1-superseded.md`, `shared-code-plan-2.md` … `-6.md`, `-5-cleanup.md`, `code-sharing-reuse-v4.md` | Multi-iteration shared-code planning series; superseded by the realised `docs/refactor/phase-3…6` work. |

## Completed refactor phase plans (`refactor/`)

Implementation plans for refactor phases whose work has fully landed — the plan
is now history; the code is the truth. The *active* refactor design records
remain under [`../refactor/`](../refactor/).

`refactor/phase-1-boilerplate-infrastructure.md` (superseded macros, removed) ·
`refactor/phase-7-library-modernisation.md` ·
`refactor/phase-9-s3-sigv4-openssl.md` ·
`refactor/phase-10-dashboard-jansson.md` ·
`refactor/phase-12-shared-file-serve.md` ·
`refactor/phase-13-aio-task-dispatch.md` ·
`refactor/phase-14-table-driven-metrics.md` ·
`refactor/phase-15-unified-namespace-layer.md` ·
`refactor/phase-16-unified-prop-store.md` ·
`refactor/phase-17-error-response-macro-collapse.md` ·
`refactor/phase-29-blocker-readv-readscratch-corruption.md` (resolved — was a
stale-object build artifact, not a code bug) ·
`refactor/phase-29-read-throughput-bottlenecks.md` (analysis superseded by the
implemented Phase 1/2/4 pipelining; see the live `../refactor/phase-32`/`phase-33`).
