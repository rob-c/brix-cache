# Refactor programme — master overview

**Last reconciled:** 2026-09-02
**Status:** ACTIVE — implementation is mature, but the repository-wide close
gate is not green. The authoritative open-work register is
[Phase 111](phase-111-repository-work-burndown.md).

## Purpose

This directory contains both executable work plans and historical design
records. It began as the intent-centric server refactor and grew to cover the
native clients, VFS/backends, authentication, performance, packaging,
observability and the Python test infrastructure. Phase numbers record delivery
history; they are not a claim that every lower number is still active or that
two documents cannot share a phase number.

The source and live guards are authoritative when an old plan body disagrees
with a later landing record. Never build a backlog by counting unchecked boxes
without reading the status/reconciliation block in the same document.

## Current read order

1. Read [Phase 111](phase-111-repository-work-burndown.md) for the current P0/P1/P2 queue,
   exact quality failures, missing-phase reconciliation and full-document
   disposition.
2. Open the owning phase linked from the selected burn-down row for the design,
   invariants, tests and acceptance criteria.
3. Re-run the row's discovery/guard command against the current tree before
   editing. Several plans deliberately preserve old measurements.
4. After implementation, append as-built evidence to the owning phase and
   close the Phase-111 row. Do not rewrite historical rationale into an
   inaccurate story of what was originally planned.

## Current programme state

| Area | State | Owning records |
|---|---|---|
| Intent/path/auth/config foundations | implemented | Phases 2–6, 8, 11, 18, 21–25 |
| Core protocol and resilience work | mostly implemented | Phases 31–53; explicit client/performance tails remain |
| VFS and backend architecture | active | Phases 54–64 are historical foundations; Phases 71, 80, 91, 104, 105, 107 and 108 carry current work |
| CVMFS/OCI/RPM distribution | implemented with dependency-gated extensions | Phases 68, 83–87, 93, 96 and OCI/RPM Phase 104 |
| Test orchestration | active migration | Phases 4, 81 and `testsuite-modernization-plan.md` |
| Maintainability | regressed from a previously green close | Phases 38/72–79/103 plus the current Phase-111 offender list |
| Monitoring vocabulary | Phase 110 complete; compatibility removal planned | Phases 110 and 112 |

The immediate baseline is not green: full pytest collection and the lifecycle
port-ledger tests pass, but five native and five Python files exceed their size
caps. The Python CCN and higher-order Cognitive/NPath/Halstead/nesting gates are
green. Exact names and acceptance commands live in Phase 111.

## Phase/reference rules

- Phases 1, 7, 9, 10 and 12–17 are completed records archived under
  [`../_archive/refactor/`](../_archive/refactor/).
- Phase 0 references are local subphases inside an owning plan.
- Phase 67 and Phase 69 are TSV move maps, not absent Markdown plans.
- Phase 73/74 records are embedded in Phase 72; Phase 76 is embedded in Phase
  75. Cite the owning document and section.
- [Phase 112](phase-112-observability-compatibility-removal.md) is the planned observability compatibility-removal phase required
  by Phase 110's self-deleting guards.
- [Phase 113](phase-113-webdav-lock-mutation-offload.md) owns the mutation-safe WebDAV LOCK offload deliberately excluded
  from Phase 109.
- [Phase 114](phase-114-credential-artifact-lifecycle.md) owns credential TTL/reaping; old Phase-108 text pointing that work
  at Phase 109 was incorrect.
- Duplicate numbers 4, 37, 52, 64, 100, 103, 104 and 105 are intentional.
  Always reference the full filename, not the number alone.

## Active phase map

| Work | Primary document | Current boundary |
|---|---|---|
| HTTP/3/QUIC | `phase-19-http3-quic.md` | dependency/use-case gated |
| SHM management tail | `phase-20-shm-kv-management.md` | TPC sizing and atomic RMW decision |
| Dynamic upstream tail | `phase-23-dynamic-upstreams.md` | active-backend DELETE semantics |
| Bounded read memory/performance | `phase-31-memory-budget-streaming.md` | readv/pgread window close |
| Data-plane performance evidence | `phase-32-data-plane-perf-parity.md`, `phase-33-perf-optimization-post-feature-complete.md` | software tail plus external hardware lanes |
| Stock GSI client | `phase-48-native-client-xrdsecgsi-interop.md` | clean-room crypto implementation |
| Client code sharing | `phase-49-client-code-sharing.md` | copy/walk and residual reorganization |
| Test lifecycle | `phase-4-bucket-1-inventory.md`, `phase-81-test-server-registry.md` | direct-launch/inline-config burndown |
| gsiftp storage driver | `phase-91-gsiftp-storage-backend.md` | production v1 implemented; optional protocol expansions documented |
| Coverage | `coverage-fast-tier-plan.md` | 68.9% measured baseline; blocking 67% floor |
| VFS spec alignment | `phase-104-vfs-spec-alignment.md` | rebaseline after Phases 107/108 |
| Config surface wave 2 | `phase-105-config-surface-wave-2.md` | W4.3/W6/W7/W9 |
| VFS mutation verbs | `phase-107-vfs-mutation-surface-completion.md` | full-tier/live close evidence |
| VFS consolidation | `phase-108-vfs-consolidation.md` | W2–W4 |
| Monitoring compatibility | `phase-112-observability-compatibility-removal.md` | release-window gated removal |
| LOCK offload | `phase-113-webdav-lock-mutation-offload.md` | decision/measurement gated |
| Credential lifecycle | `phase-114-credential-artifact-lifecycle.md` | deferred Phase-108 stretch |
| Optional hardening | `seccomp-exec-broker-plan.md` | Option B unimplemented |

## Historical material

Historical plans are intentionally retained because they explain invariants,
failed approaches, compatibility decisions and test design. A document marked
historical or superseded is not dead documentation; it is simply not a second
work queue. The Phase-111 full-document disposition identifies every such file.

Generated inventories (`testsuite-surface-inventory.*`, baseline JSON and phase
map TSV files) must be regenerated from their owner tooling rather than edited
by hand.

## Documentation close gate

After changing this directory, run:

```bash
python3 tools/ci/check_doc_links.py
python3 tools/ci/check_doc_paths.py
```

Then verify that every newly introduced phase reference either names an existing
document/artifact, an archived phase, or an explicitly identified embedded
subphase. A bare future phase number with no owner is a documentation defect.
