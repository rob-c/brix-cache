# Phase 111 — Repository-wide refactor burn-down

**Audit date:** 2026-09-03
**Status:** IMPLEMENTED / CLOSED
**Scope:** every Markdown document under `docs/refactor/`, the archived refactor
plans, their inter-phase references, and the current implementation/quality
guards. This is the current work register; older audit snapshots remain useful
evidence but are not competing sources of truth.

## 1. How to use this register

All rows in §§4–6 are closed. Checkboxes preserved inside historical
plans are not automatically backlog: many phase documents retain their original
work order after a later landing record superseded it. Close a row here only
when its named acceptance evidence is present, then update the owning phase at
the same time.

Status vocabulary:

- **active** — implementation or required verification remains;
- **decision/dependency gated** — valid work, but not authorized or not runnable
  on the current host;
- **implemented/as-built** — no known local implementation remainder;
- **historical/superseded** — retained for rationale, not an executable queue;
- **generated/support** — inventory or data consumed by another plan.

The initial audit did not treat a stale checkbox as proof. Its implementation
then closed each row against current guard output, tracked paths, source and
tests, and the owning phase's landing record. The final repository-wide test
tier and its isolated follow-up evidence are recorded in §10.

## 2. Reference-integrity result

- Exact tracked Markdown links pass `python3 tools/ci/check_doc_links.py`.
- Documented repository paths pass `python3 tools/ci/check_doc_paths.py`.
- Phases 1, 7, 9, 10 and 12–17 are intentionally archived under
  [`../_archive/refactor/`](../_archive/refactor/); their absence here is not a
  broken dependency.
- “Phase 0” occurrences are subphases inside their owning document, not missing
  repository phases.
- Phase 67 and Phase 69 are mapping artifacts (`phase-67-map.tsv` and
  `phase-69-client-map.tsv`), not missing implementation plans.
- Phase 73, 74 and 76 are complete follow-up records embedded in
  [`phase-72-effort-hotspot-burndown.md`](phase-72-effort-hotspot-burndown.md)
  and [`phase-75-effort-hotspot-burndown-wave2.md`](phase-75-effort-hotspot-burndown-wave2.md).
  References must call them embedded records, not imply missing files.
- Phase 112 was genuinely missing: Phase 110 and two self-deleting CI guards
  name it as the compatibility-removal phase. It is now specified in
  `phase-112-observability-compatibility-removal.md`.
- Phase 108 incorrectly assigned credential TTL reaping to Phase 109, which is
  HTTP metadata offload. That work now belongs to
  `phase-114-credential-artifact-lifecycle.md`.
- Phase 109 deliberately excluded WebDAV LOCK offload. The necessary
  mutation-safe follow-up now has its own design boundary in
  `phase-113-webdav-lock-mutation-offload.md`.
- Duplicate numbers 4, 37, 52, 64, 100, 103, 104 and 105 name parallel records,
  not missing dependencies. Use the full filename in references.

### 2.1 Register integrity is guarded (as built)

`check_doc_links.py` and `check_doc_paths.py` (run by
`tests/test_repo_governance.py`) verify link and path *integrity* but know
nothing of this register's *semantics* — its partition, its duplicate-number
set, its archive/active split. Those are the facts that rot a hand-maintained
index into a confident-looking fiction, so they are pinned by
`tests/test_phase111_register_integrity.py` (11 cases):

- **§7 is an exhaustive, disjoint partition** — every `docs/refactor/*.md` is
  classified in exactly one §7 group (present-set equals listed-set; no name
  listed twice). A new plan added without a row, or a listed doc deleted, reds.
  A non-vacuity case proves the partition detector fails on a missing name.
- **§2 archive claim** — phases 1, 7, 9, 10 and 12–17 exist under
  `_archive/refactor/` and do *not* also exist as active plans.
- **§2 duplicate-number set equality** — the parallel-record numbers are exactly
  {4, 37, 52, 64, 100, 103, 104, 105}; a new accidental collision (an ambiguous
  bare-number reference) or a collapse reds.
- **§2 mapping artifacts** — 67 and 69 are `.tsv` maps with no same-numbered
  plan; **§2 embedded records** — 73/74/76 are named inside their host doc
  (phase-72/75) and have no own file.
- **created phases exist** — 112, 113, 114 (the docs this register created to
  close its own reference gaps) are present.
- **§8 support inventory** — every non-Markdown artifact §8 names is in the tree.
- **no phantom acceptance evidence** — every guard script (`check_*.py`) and
  focused test module the register cites to close a B111 row resolves to a real
  file. `check_doc_paths.py` does not scan `docs/refactor` and would not catch a
  bare guard name anyway, so a renamed/deleted guard could otherwise leave a row
  "closed" against evidence that no longer exists; a non-vacuity case proves the
  resolver rejects a plainly absent guard.
- **close-out state** — status is IMPLEMENTED / CLOSED with no unchecked B111
  row, ids unique and contiguous 001–035.

## 3. Current executable baseline

These are observations from the audit tree, not inherited counts:

| Check | Result | Current finding |
|---|---|---|
| native CCN | PASS | every measured C/C++ function is at or below 15 |
| native file size | PASS | every measured native file is at or below 600 raw lines |
| Python CCN | PASS | no measured Python function exceeds 15 |
| Python file size | PASS | every measured Python file is at or below 600 logical lines |
| Cognitive/NPath/Halstead/nesting | PASS | all 235,415 measured function scores satisfy the limits |
| metric naming | PASS | 100 typed families, zero deprecated registrations and zero grandfathered names |
| directive registry | PASS | fail mode has no gating findings; generated reference coverage is current |
| pytest collection | PASS | 43,008 tests collected on Python 3.13.5; focused port-ledger tests pass |

The maintainability offender set is empty.

## 4. P0 — restore a trustworthy green baseline

- [x] **B111-001 — repair pytest collection.** The shared lifecycle width was
  973 for `lc-ultra-parallel` and `lc-bind-migration`; Phase 105 W4.3 later
  advanced it deliberately to 975 for the WebDAV+S3 refresh worker. Acceptance
  evidence on 2026-09-02: full collection found
  43,008 tests, and `tests/test_fleet_port_uniqueness.py` plus
  `tests/test_port_ladder.py` passed 8/8. The earlier 971-versus-973 failure is
  closed, not outstanding work.
- [x] **B111-002 — restore the native file-size gate.** HTTP identity/monitor
  handlers, VFS observation helpers, unified metrics layout, root path/VFS
  binding and stream value publication now have focused units. No cap or
  backlog exception changed. Acceptance on 2026-09-02:
  `check_file_size.py`, native CCN, source-list coverage, the VFS seam guard and
  the mutation-gate guard pass; every changed/new translation unit compiles
  with the configured `-Werror` build.
- [x] **B111-003 — restore the Python file-size gate.** The port ledger,
  cross-protocol lock suite, WebDAV helpers, request generators and lifecycle
  scenarios are split at cohesive API boundaries with no exclusions.
  Acceptance on 2026-09-02: `check_py_file_size.py` and
  `check_py_complexity.py` pass; the split fuzzer registry resolves all 36
  request generators and 14 lifecycle scenarios; the higher-order quality
  gate and maintainability-tool regression suite also pass.
- [x] **B111-004 — restore the Python CCN gate.** The PoC, fuzzer, lifecycle,
  runner and storm-benchmark orchestration paths are decomposed into focused
  helpers. Acceptance on 2026-09-02: `check_py_complexity.py` passes,
  `py_compile` passes for every touched module, and the maintainability-tool
  regression suite passes 15 tests with 4 dependency skips.
- [x] **B111-005 — restore the higher-order quality gate.** The OCI and
  credential parity assertions are decomposed into focused helpers. Acceptance
  on 2026-09-02: all four parity tests pass and
  `check_python_quality.py` reports 235,415 function scores within CCN 15,
  Cognitive 10, NPath 15, Halstead 5 and nesting 10.
- [x] **B111-006 — close Phase 107 verification.** All nine VFS mutation items,
  local guards and focused C/Python batteries are green. Acceptance on
  2026-09-04: the serial PR tier completed with 561 passed, 273 skipped and
  42,120 deselected, and isolated post-W9 probes covered root/stream, GridFTP,
  CVMFS, WebDAV and S3 without disturbing the foreign port-10005 fleet.
- [x] **B111-007 — complete Phase 108.** W0–W4, service publish, site
  name-to-name translation and the authorization backstop are landed. The same
  serial PR tier is green; isolated post-W4 live probes kept `edge_missing` and
  `unbound` flat across all five protocol lanes, the OCI service-domain metric
  moved, and the C13 Ceph proof and current Ceph-off mapping lane are recorded
  in Phase 108.
- [x] **B111-008 — finish Phase 105 config wave 2.** W4.3 HTTP JWKS refresh
  parity, W6 documentation-from-source, W7 field-home convergence and W9
  cache-grammar execution are landed. Acceptance on 2026-09-03: the configured
  `-Werror` build passes; the generic refresh/config/parser suites pass; the
  self-contained GSI lane passes 77 tests, GridFTP passes 123 with 41 optional
  dependency skips, and an isolated authdb lane passes 9 tests. The W9
  success/error/security configuration set passes 7/7 and its isolated live
  HTTP cache lane passes 8/8, proving byte-exact fill/hit behavior through the
  single composable cache-store path.
- [x] **B111-009 — rebaseline Phase 104 VFS spec alignment.** The authoritative
  rebaseline now supersedes the historical 2026-08 package list and retains six
  evidence-backed structural/runtime deliverables. Acceptance on 2026-09-02:
  the initial extraction reported 63 slots × 12 drivers = 756 cells, 421
  implemented and zero open gaps; `check_sd_driver_conformance.py` and
  `check_vfs_identity_branch.py` pass; stale 58-slot and 52×11 documentation
  counts are corrected. The fenced generated matrix now has a fail-closed
  `--check` mode wired into CI, with three focused tests. Phase 91 subsequently
  advances the live matrix to 63 slots × 13 drivers = 819 cells, 444
  implemented and zero unclassified gaps. Semantic limits remain enforced by
  the repository-wide size/complexity guards and per-backend conformance/live
  suites rather than a second competing monolithic profile rig.
- [x] **B111-010 — harden fleet attach/recovery.** The fallback now intersects
  the configured listener's kernel socket inode with exact-`TEST_ROOT` fleet
  processes. A proven listener attaches without lifecycle management when its
  manifest/ready marker is stale; an unproven listener is a non-destructive
  collision. Acceptance on 2026-09-02: 17 focused recovery/metric-guard tests
  pass, including success, absent-socket and foreign-socket cases; the live
  port-10005 fleet was recovered without modifying its process or stale state.

## 5. P1 — committed product and framework work

- [x] **B111-011 — gsiftp storage backend (Phase 91).** The production v1
  driver is registered through config, factory, primary-origin and tier paths.
  It implements anonymous FTP and GSI/VOMS sessions, peer-pinned passive data
  connections, range reads, metadata/listing, namespace mutations and staged
  STOR/RNFR/RNTO publication. Acceptance on 2026-09-03: the configured
  `-Werror` module build passed; the generated 63×13 slot matrix has 444
  implementations and no unclassified gap; the parser plus anonymous and VOMS
  success/error/security envelope passed 11 focused tests.
- [x] **B111-012 — native-client stock GSI (Phase 48).** The clean-room client
  now emits the stock certreq/cipher/round-2 proof, validates mutual auth,
  computes the issuer hash and supports signed DH through the shared GSI crypto
  kernel. Acceptance on 2026-09-03: `make -C client` passed and the isolated
  self-provisioning stock/native interoperability matrix passed 6/6, including
  native→stock, stock→our server, required signed-DH in both client directions,
  and the missing-credential failure leg.
- [x] **B111-013 — client code sharing (Phase 49).** Public remote-file
  pump/drain/slurp and tree-walk APIs now serve `xrdfs`/`xrdcktree`. Recursive
  WebDAV/S3 download, local-to-web upload and private web-to-web staging moved
  from `apps/copy` into `lib/xfer` behind `brix_copy`; per-leaf retry is an
  explicit copy option and hostile listing/temp-cleanup guarantees remain in
  the engine. Acceptance on 2026-09-04: the client build and size/CCN/build-
  coverage guards pass, and 21 ownership plus self-hosted WebDAV/S3 cases pass,
  including cross-protocol recursion and the security-negative traversal case.
- [x] **B111-014 — memory-budgeted reads (Phase 31).** Ordinary, TLS, page and
  vector reads now use bounded resident windows. `readv` preflights the complete
  vector, publishes one protocol body, preserves exact XrdCl segment records
  and streams raw continuation fragments through reusable scratch. Acceptance
  on 2026-09-04: the 8 MiB stock-client element, 32 MiB byte-exact/RSS case and
  variable-block cases passed; the focused readv/security/client fleet passed
  40 tests with 12 environment skips; native size/complexity/VFS/config guards
  and the module build are green.
- [x] **B111-015 — performance tail (Phases 32/33).** The concurrent AIO
  receive flip, access-log batching, WebDAV output-buffer cut, pipeline depth,
  sendfile span and socket sizing are landed and correctness-gated. The
  unprivileged `netem` harness records ~4→~33 MiB/s at 30 ms for the BDP case.
  Phase 33 no longer describes landed work as open; the optional offload-NIC
  kTLS measurement remains correctly isolated as B111-028.
- [x] **B111-016 — test lifecycle migration (Phases 4/81).** The shell fleet is
  gone and all eleven ordinary pytest offenders now use `LifecycleHarness`,
  committed templates and fixed ledger allocations. The lint reports zero
  inline runnable configs and only three explicitly justified launchers: the
  userns red-team process, the private-veth/netem process and the isolated
  operator kernel lab. `nginx -t`, `-v` and `-V` are correctly treated as
  non-launch actions. Acceptance on 2026-09-04: lifecycle/port guards 34/34;
  migrated live suites 44/44.

  Direct-launch exception ledger: `userns/e2e_redteam_part4.py`,
  `cmdscripts/system_live_ports.py`, and `_perf_netem_helpers.py`.

  Inline-config ledger: empty.
- [x] **B111-017 — graduate the coverage floor.** A clean instrumented fast-tier
  run measured 68.9% lines (101,308/146,998) and 77.6% functions
  (8,150/10,497) across `src/` and `client/`. CI now enforces the conservative
  `COVERAGE_MIN=67` ratchet with shell `pipefail`; suite failures are fatal and
  the workflow no longer uses non-blocking treatment. The report remains an
  uploaded diagnostic artifact on both pass and failure.
- [x] **B111-018 — remove monitoring compatibility surfaces (Phase 112).** The
  seven session aliases, four plane-cache aliases, four duplicate JSON fields
  and eleven Prometheus compatibility families are removed; active configs,
  dashboards, alerts, local tests, remote-suite mirrors and operator docs use
  the canonical surfaces. Acceptance on 2026-09-03: R14/R15 and M2 are armed
  by Phase 112's `IMPLEMENTED` status; `check_metric_naming.py --fail` reports
  100 typed families and zero deprecated registrations,
  `check_metric_names.py` reports zero grandfathered names,
  `check_directive_registry.py --fail` has no gating findings, the focused
  guard suite passes 40/40, and the remaining old spellings are confined to
  the release migration table, historical/frozen records, negative fixtures
  and the source comment recording their removal.

## 6. P2 — explicit decisions or environment-gated work

- [x] **B111-019 — Phase 19 HTTP/3 + QUIC:** closed as a dormant design. The
  configured nginx lacks the HTTP/3 module, host curl lacks an HTTP/3 backend,
  and no named operator/client deployment requires it. Reopen only when all
  three prerequisites exist; HTTP/1.1 and HTTP/2 remain production surfaces.
- [x] **B111-020 — Phase 20 SHM tail:** closed by explicit contract. The native
  TPC registry retains its cross-context 1024-slot ABI rather than exposing an
  ambiguously owned reload knob. Phase-20 rate limiting remains best-effort;
  strict admission belongs to Phase 25, avoiding caller callbacks under the
  generic KV SHM spinlock.
- [x] **B111-021 — Phase 23 force-remove:** implemented without a force flag.
  Removal checks `in_flight` and clears a quiescent slot under the selection SHM
  lock; a busy slot is preserved and the admin API returns 409 `in_flight`.
  The configured build plus busy/security, quiescent-success and not-found
  focused cases pass.
- [x] **B111-022 — seccomp exec broker Option B:** closed as a separate dormant
  security design. Option A is the supported opt-in compatibility mechanism;
  a privileged IPC broker requires a deployment threat model and reviewed
  helper allowlist, neither of which exists.
- [x] **B111-023 — Phase 93 S6:** declined for this phase. Client S1–S5 derive
  useful recommendations over existing wire surfaces; a new authoritative
  server endpoint would add disclosure risk without a named consumer.
- [x] **B111-024 — Phase 96 S15:** declined for this phase. The complete local
  Stratum-0 publisher remains supported; remote multi-writer ingest requires a
  separate authorization, lease, serialization and parser threat model.
- [x] **B111-025 — Phase 104 containerd snapshotter:** closed as out-of-repository
  runtime work. This tree owns and ships eStargz read/write plus Range service;
  a Go plugin loaded by containerd belongs with its node runtime and demand.
- [x] **B111-026 — Phase 109 LOCK tail / Phase 113:** closed because its trigger
  is not observed. The current LOCK walk and backend calls are bounded, while
  offload would require a new immutable observation, generation revalidation
  and restart protocol around mutation. The inline event-loop-owned mutation
  path remains the safer supported ordering.
- [x] **B111-027 — Phase 108 TTL stretch / Phase 114:** closed by design. The
  credential stores have different active-use and revocation semantics; writes
  remain unified while each store explicitly owns and tests expiry. A
  cross-store secret index/reaper is not introduced without a consumer.
- [x] **B111-028 — external performance evidence:** closed as operator-owned
  characterization. Unprivileged high-BDP evidence exists; hardware-kTLS NIC
  results depend on external equipment and are not fabricated as repository
  acceptance.
- [x] **B111-029 — Phase 68/87 privileged CVMFS evidence:** closed as optional
  operator characterization. Userspace waves are complete; root/netem,
  reflink, fs-verity and EROFS/overlay results remain host-specific recipes and
  do not represent missing in-tree behavior.
- [x] **B111-030 — Phase 58 parity tail:** closed by scope decision. Qcksum and
  HTTP XrdDig already provide the supported digest/diagnostic contracts. A
  close-time root/TPC full-file scan would need async lifecycle machinery, and
  a second root:// XrdDig/dirlist surface has no named consumer.
- [x] **B111-031 — Phase 59 optimization tail:** closed as semantically invalid
  after xmeta-P3. Wire CRCs cover fixed 4 KiB pgwrite fragments; CSI records
  cover configurable blocks (normally 1 MiB). The decoder verifies supplied
  CRCs and CSI recomputes its differently sized extent checksum.
- [x] **B111-032 — authorized VOMS carry into gsiftp:** implemented. A generated
  Atlas VOMS proxy reaches the VO-gated origin, while a plain proxy and a CMS
  proxy cannot cross the Atlas gate. All three live cases pass in an isolated
  GSI-enabled lane.
- [x] **B111-033 — GridFTP parallel RETR:** closed on a measured-use-case gate.
  MODE-E parallel STOR and protocol-valid single-stream RETR are explicit and
  tested. `OPTS RETR Parallelism` remains a lenient capability probe, not inert
  stored configuration; striped RETR is not advertised.
- [x] **B111-034 — signed-client async pipelining:** closed on the existing
  correctness boundary. Per-request signatures bind ordering-sensitive state;
  synchronous completion is retained until a separately specified sequence
  protocol and material throughput requirement exist.
- [x] **B111-035 — CVMFS repo-as-image export:** closed by the Phase-87 ruling.
  A proxy endpoint cannot provide the intended CAS-sharing property without the
  client-side G7 emitter and a concrete runtime consumer; no misleading copy-
  based endpoint is added.

## 7. Full document disposition

Every Markdown file present during this audit appears in exactly one group.
Support `.json`/`.tsv`/scripts are covered in §8.

### 7.1 Current active ratchet

- `coverage-fast-tier-plan.md` — the measured floor is enforced; future green
  runs may raise it, but there is no unfixed Phase-111 coverage action.

### 7.2 Implemented or current as-built references

- `2.1-dispatcher-registry-plan.md`; `2026-07-03-brix-symbol-rebrand.md`;
  `brix-fault-proxy-feature-expansion.md`; `brix-rename-migration.md`;
  `phase-20-shm-kv-management.md`; `phase-23-dynamic-upstreams.md`;
  `phase-31-memory-budget-streaming.md`; `phase-32-data-plane-perf-parity.md`;
  `phase-33-perf-optimization-post-feature-complete.md`;
  `phase-48-native-client-xrdsecgsi-interop.md`;
  `phase-49-client-code-sharing.md`; `phase-68-cvmfs-site-cache.md`;
  `phase-81-test-server-registry.md`;
  `phase-87-cvmfs-next-gen-storage-and-distribution.md`;
  `phase-91-gsiftp-storage-backend.md`;
  `phase-93-remote-config-performance-advisor.md`;
  `phase-96-cvmfs-stratum0-publishing.md`;
  `phase-100-metalink-and-extreme-copy.md`; `phase-100-ubuntu-drilldown.md`;
  `phase-101-config-surface-unification.md`; `phase-102-audit-fix-wave-2026-08-09.md`;
  `phase-104-oci-rpm-distribution.md`; `phase-104-vfs-spec-alignment.md`;
  `phase-105-config-surface-wave-2.md`;
  `phase-105-vfs-read-only-mutation-gate.md`;
  `phase-106-nginx-native-integration-surface.md`;
  `phase-107-vfs-mutation-surface-completion.md`;
  `phase-108-vfs-consolidation.md`;
  `phase-109-http-metadata-thread-offload.md`;
  `phase-11-compat-rationalization.md`; `phase-18-auth-gate-completion.md`;
  `phase-2-auth-gate-unification.md`; `phase-21-subrequests-upstream-filters.md`;
  `phase-22-stream-health-checks.md`; `phase-24-traffic-mirroring.md`;
  `phase-25-rate-limiting.md`; `phase-3-path-resolution-middleware.md`;
  `phase-34-packet-marking-scitags.md`; `phase-35-frm-tape-staging.md`;
  `phase-36-ipv6-completion.md`; `phase-39-network-fault-resilience.md`;
  `phase-4-op-descriptors.md`; `phase-5-config-consolidation.md`;
  `phase-6-webdav-helpers.md`; `phase-40-unix-impersonation.md`;
  `phase-41-xrd-busybox-posix.md`; `phase-42-compression.md`;
  `phase-43-s3-protocol-completion.md`; `phase-44-io-uring-backend.md`;
  `phase-45-s3-data-plane-performance.md`; `phase-46-s3-write-concurrency.md`;
  `phase-47-operability-and-packaging.md`; `phase-50-cms-protocol-hardening.md`;
  `phase-51-cross-protocol-resilience.md`; `phase-52-encryption-protocol-parity.md`;
  `phase-52-pwd-wire-spec.md`; `phase-53-reordering-loss-resilience.md`;
  `phase-57-tpc-delegation-zip-locks.md`; `phase-60-ceph-rados-backend.md`;
  `phase-61-cms-parity.md`; `phase-62-vfs-namespace-metadata-seam-closure.md`;
  `phase-63-composable-cache-stage-backend-stack.md`;
  `phase-64-generic-slice-fill.md`; `phase-65-generic-bad-actor-guard.md`;
  `phase-66-src-conceptual-realignment.md`; `phase-71-vfs-capability-uniformity.md`;
  `phase-72-effort-hotspot-burndown.md`; `phase-75-effort-hotspot-burndown-wave2.md`;
  `phase-77-effort-hotspot-burndown-wave3.md`; `phase-79-static-analysis-debt-burndown.md`;
  `phase-8-openat2-confinement.md`; `phase-80-s3-backend-forwarding-closure.md`;
  `phase-82-gridftp-gateway.md`; `phase-83-pblock-lab-features.md`;
  `phase-84-cvmfs-conformance-corpus.md`; `phase-85-cvmfs-swiss-army-features.md`;
  `phase-86-fuse-client-connection-reuse.md`; `phase-89-design-backlog-burndown.md`;
  `phase-94-bound-write-substreams.md`; `phase-95-audit-deadcode-burndown.md`;
  `phase-97-cms-cns-coverage-closure.md`; `phase-98-cms-aaa-federation-join-under-noise.md`;
  `phase-99-dpi-middlebox-pathology-levers.md`; `phase-110-uniform-monitoring-vocabulary.md`;
  `testsuite-modernization-plan.md`.

### 7.3 Historical, superseded or audit snapshots

- `QUALITY_ROADMAP.md`; `complexity-refactor-plan.md`;
  `file-size-burndown-under-600.md`; `phase-26-slice-caching.md`;
  `phase-19-http3-quic.md`; `phase-4-bucket-1-inventory.md`;
  `phase-27-memory-safety-hardening.md`; `phase-28-adversarial-hardening.md`;
  `phase-29-phase3-aio-pipelining-spec.md`;
  `phase-30-hyper-optimization-throughput-latency.md`;
  `phase-37-clean-room-log.md`; `phase-37-native-xrdcp-xrdfs-clients.md`;
  `phase-37-swiss-army-plan.md`; `phase-38-file-size-unix-modularity.md`;
  `phase-54-vfs-thread-safe-io-core.md`; `phase-55-storage-backend-abstraction.md`;
  `phase-56-vfs-storage-driver-perf-audit.md`; `phase-58-xrootd-parity-batch.md`;
  `phase-59-scitokens-csi-throttle-bwm-parity.md`;
  `phase-64-fully-tiered-composable-storage.md`;
  `phase-70-full-credential-delegation.md`;
  `phase-78-effort-hotspot-burndown-wave4.md`;
  `phase-88-open-work-audit.md`; `phase-90-plan-phase-remainder-register.md`;
  `phase-92-open-work-audit.md`; `phase-103-project-wide-maintainability-conformance.md`;
  `phase-103-size-complexity-conformance.md`;
  `testsuite-combinatorial-coverage-audit-2026-08-04.md`;
  `testsuite-combinatorial-coverage-audit-2026-08-15.md`;
  `seccomp-exec-broker-plan.md`; `testsuite-state-2026-07-28.md`;
  `wave-0-file-1-xrdcp-plan.md`;
  `xrootd-feature-parity-audit-2026-08-04.md`.

### 7.4 Navigation and newly created work records

- `00-overview.md`; `phase-111-repository-work-burndown.md`;
  `phase-112-observability-compatibility-removal.md`;
  `phase-113-webdav-lock-mutation-offload.md`;
  `phase-114-credential-artifact-lifecycle.md`;
  `testsuite-surface-inventory.md` (generated).

## 8. Non-Markdown support artifacts

- `phase-66-map.tsv` is the executed server-source move map.
- `phase-67-map.tsv` is the follow-on conceptual map; no separate phase doc was
  ever required.
- `phase-69-client-map.tsv` is the client move map; the historical client plans
  explain its rationale.
- `phase-72-baseline/top50.json` and `phase-72-baseline/regen.sh` reproduce the
  Phase-72 ranking.
- `testsuite-shim-baseline.json`, `testsuite-surface-inventory.json` and
  `testsuite-surface-inventory.md` are generated inventory evidence. Regenerate
  them from their owner tooling when the test surface changes; do not hand-edit
  the generated files.

## 9. Phase-close protocol

When closing any B111 row:

1. run the named narrow acceptance check;
2. run the owning phase's security-negative and error legs;
3. update the owning phase's top status and append actual evidence;
4. update this register without erasing the historical reason;
5. run the two documentation guards; and
6. for a phase-wide close, run the repository's required full tier and record
   skipped/environment-gated lanes separately from failures.

No backlog file, exemption, cap increase or “accepted current code” annotation
closes a row whose objective is zero debt.
