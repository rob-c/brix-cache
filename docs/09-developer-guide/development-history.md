# Development History, Decisions & Lessons Learnt

**Date:** 2026-07-15
**Status:** Living master index. This is the entry point for "why does this
subsystem look the way it does" and "has someone hit this before" questions —
read the linked document for your area before spending time rediscovering
something already known.
**Origin:** synthesized from ~234 session-memory records accumulated across
the project's development (2026-04 through 2026-07-15), grouped by subsystem
and rewritten as narrative history. Individual per-topic memory files still
exist as a secondary, more granular record (see "Relationship to the memory
system" below), but this set of documents is now the canonical, in-repo
record of *why* — decisions, incidents, and lessons — as opposed to the
`docs/refactor/phase-NN-*.md` docs and code, which are the canonical record
of *what* (specs and current-state implementation detail).

None of these documents repeat implementation detail already covered by a
`docs/refactor/phase-NN-*.md` spec or a `docs/09-developer-guide/*.md`
reference doc — they link out to those instead and focus on the parts that
don't otherwise survive: the reasoning behind a design choice, the incident
that produced a guardrail, the bug that cost a day to find, the thing that's
still open.

---

## The six topic documents

| Document | Covers | Size |
|---|---|---|
| [History — Protocols & Feature Phases](history-protocols-and-feature-phases.md) | Native XRootD/pgread-pgwrite wire fidelity, S3, WebDAV extras, CMS mesh, proxy mode, pipelining, mirroring, dashboard, monitoring/AF-bridging, SciTags, federation (Pelican) | 59 KB |
| [History — Storage & Caching](history-storage-and-caching.md) | VFS seam closure, composable cache tiers, pluggable backends (pblock, Ceph/RADOS, S3, CVMFS), FRM/tape staging dissolution, unified cache state | 54 KB |
| [History — Client Tooling](history-client-tooling.md) | Native xrdcp/xrdfs, FUSE (xrootdfs), CVMFS native client (brixMount), GSI client interop, the "swiss army client" vision, robustness/UX/firewall/mount-speed work | 41 KB |
| [History — Testing & Incidents](history-testing-and-incidents.md) | Test harness evolution, conformance suites (WLCG x509/token, multiuser perms), chaos/reload testing, load testing, CMS/AAA federation join under an impaired link, production postmortems (incl. the "host overloaded" banned-diagnosis incident and the cross-lane SIGTERM: lane ownership is a path, not a substring) | 80 KB |
| [History — Security & Credentials](history-security-and-credentials.md) | Auth gate ordering, credential forwarding, TPC delegation (native + WebDAV), impersonation, GSI/TLS negotiation, ARC-CE httpg front proxy + `$brix_delegated_cred` / hashed-CA-dir directives, vulnerabilities found & fixed, XrdAcc | 62 KB |
| [History — Build, Infra & Decisions](history-build-infra-and-decisions.md) | Build system mechanics, packaging, codebase-wide refactors (rebrand, src realignment, hardening waves), **and the standing working agreements for AI agents in this repo** | 30 KB |

These sit alongside the five earlier `lessons-*.md` documents, which remain
the deep-dive references for their specific eras and are cross-linked from
the topic docs above rather than duplicated:

| Document | Covers |
|---|---|
| [lessons-migration-era-2026.md](lessons-migration-era-2026.md) | Structural migrations phases 55–66: storage-driver abstraction, VFS seam closure, composable-tier/FRM dissolution, `src/` conceptual realignment |
| [lessons-tpc-vfs.md](lessons-tpc-vfs.md) | Native TPC (GSI/async/TLS/delegation) and VFS storage-driver field guide |
| [lessons-codebase-hardening-2026-06.md](lessons-codebase-hardening-2026-06.md) | Whole-tree hardening pass: link-time hardening, `safe_size.h`, libFuzzer, ASan/UBSan, sandboxing |
| [lessons-security-reaudit-and-cleanup.md](lessons-security-reaudit-and-cleanup.md) | Security re-audit findings and cleanup |
| [lessons-brix-rebrand-and-suite-stabilization-2026-07.md](lessons-brix-rebrand-and-suite-stabilization-2026-07.md) | The BriX symbol rebrand and post-merge fast-suite stabilization |

---

## Open items across all six documents

The single most important thing to check before starting work in an
unfamiliar area: each history document ends with an open-items table. As of
2026-07-15 the notable standing ones are:

- **Native TPC-over-GSI delegation** — RESOLVED 2026-07-19 (a `tpc.org`
  host-string mismatch, not a push-model limitation; see the RESOLVED section
  at the top of
  [History — Security & Credentials](history-security-and-credentials.md)).
- **Backend delegation (phase-70/90)** — all locally-doable legs closed
  2026-07-27; only the S3-STS and krb5 origin legs remain, container-blocked
  (`docs/refactor/phase-90-plan-phase-remainder-register.md`).
- See each document's closing table for the rest (S3 metadata-parity scoping
  decisions left undone, etc.). The hybrid-mesh WebDAV/XrdHttp crash was
  resolved by surface retirement 2026-07-20 (hyper-hardening § A-2).

## Relationship to the memory system

Claude's per-session memory system (`~/.claude/projects/.../memory/`) still
holds ~234 individual records, most now compacted to short pointers. Going
forward:

- **For subsystem history, design rationale, and lessons learnt, consult this
  document tree first** — it is the synthesized, durable record and is
  checked into the repo (survives memory resets, is reviewable in PRs, and is
  visible to every contributor, not just an AI agent's private memory).
- The memory system's `MEMORY.md` index now points here at the top of the
  file. Individual memory files remain as a secondary, more granular log
  (exact dates, session IDs, raw incident detail) and are still useful for
  archaeology, but should not be treated as more authoritative than this
  document tree when the two overlap — this tree was written *from* the
  memory files and is the reconciled, deduplicated version.
- New project/feedback memories saved in future sessions should still go
  through the normal per-file memory flow (they're cheap and low-latency to
  write), but anything that rises to the level of a durable
  decision/lesson/incident worth a future contributor reading should also be
  folded into the relevant document above when convenient.

---

## Appendix — the folded memory index

The agent memory store used to carry one file per item below, each holding
nothing but a one-line summary and a pointer back into this tree. That is a
pointer at a pointer, so the summaries were folded in here and the files
deleted. Use this as a slug → *what happened* lookup when an old note, commit
message or transcript names one of these; the narrative itself is in the
document named by the heading.

### `history-build-infra-and-decisions.md` — Build system, packaging, refactors, working agreements

- **audit_effort_reduction_findings** — Audit-effort reduction backlog (2026-07-05) — src/client items IMPLEMENTED, tests/ items still open
- **audit_simplification_session** — 2026-07-02 audit-improvement work — core/http split, S3 conditional merge, 2 new CI guards, registry split; remaining MUST-tier follow-ups
- **brix_rebrand_executed** — BriX symbol rebrand (xrootd_->brix_) executed on main 2026-07-03; suite burned 76 failures -> 0
- **build_flag_optimization_findings** — GCC codegen/build-flag audit results — non-PIE, PGO win is structural not measurable on WSL2, gc-sections defeated by -Wl,-E; hot source already optimal
- **build_header_dep_mixed_abi** — nginx addon build does NOT track header deps — editing a widely-included struct header + incremental make = mixed-ABI crash
- **central_declaration_lists** — 2026-07-03: proto_list.h + fs_list.h — ONE X-macro declaration each for protocols and filesystems; add rows there, never hand-extend the generated tables
- **code_reduction_opportunities** — Detailed LoC reduction opportunities (1,200-1,500 LoC) via consolidating boilerplate, macros, and helper functions
- **coding_standard_no_goto_functional** — Project coding standard — NO goto + functional/modular; scope = src/ AND client/; authoritative doc + auto-pickup wiring + goto backlog
- **doc_tree_standard** — Project documentation standard — README.md in every src/ subfolder + ~100% file-header docblocks; how it was built and the bar to keep
- **docblock_deslop_backlog** — Recurring docblock de-slop task — approach + tooling; backlog is at 0 as of last sweep
- **docs_reorg_2026_06** — Docs reorganized 2026-06-13 — taxonomy/archive layout, src/ is truth, reusable linkcheck + audit recipe
- **god_header_auditability_refactor** — God-header/god-file decomposition (config.h/context.h/webdav.h/s3.h/metrics.h split into sub-structs + concern headers; module.c/origin_protocol.c/server_conf.c/drivers decomposed) — DONE, UNCOMMITTED
- **hardening_cflags_global_constraint** — module config CFLAGS apply to nginx core too, so -Werror warning flags must be nginx-core-clean; which warning flags are in vs opt-in; the silent empty-module-build trap
- **idle_cpu_timer_family** — Mesh idle-CPU / perf-test flakiness root cause = family of self-rearming timers (FRM 500ms per-worker, CMS 0ms-on-misconfig, health-check 100ms floor) that polled instead of quiescing — all 3 fixed 2026-06-15
- **maintainability_guards_program** — 2026-07-07 no-code maintainability program LANDED — guards in CI, gitignore-casualty class found+fixed, doc drift guards, ports registry, runbook
- **mega_commit_2026_07_13** — Commit 27c89e3 (2026-07-13) landed ALL previously-uncommitted work on main — any older memory saying UNCOMMITTED is stale as of this date
- **phase17_macro_collapse** — Phase 17 error-response macro collapse — completion + the message-equality gotcha for future collapse phases
- **phase27_status** — Phase 27 memory-safety & anti-abuse hardening (safe_size, scoped, readv/session/evict guards, ASAN/valgrind/fuzz/lint) — COMPLETE, valgrind found+fixed 2 real bugs
- **phase47_operability_packaging** — docs/refactor/phase-47 operability/packaging W1-W5 + S3 W6a/b/c IMPLEMENTED 2026-06-21 — key gotchas and design decisions not in the doc
- **phase66_src_realignment_executed** — phase-66 executed — src/ reorganized into 7 concept buckets; how the move tooling + gotchas work
- **phase72_burndown_implemented** — Phase-72 through -79 effort-hotspot/static-analysis burndowns (analyzer fixes + ~200-file complexity decompositions) implemented, uncommitted; only frozen-signature param residuals remain
- **pymigrate_python_migration_tools** — Pure-Python XrdCeph<->CephFS migration tools (client/apps/ceph/pymigrate since 2026-07-07) — ctypes bridge facts, delete-through purge hazard (FIXED in both C++ tools), demo-cluster pool names
- **refactor_regression_postmortem** — Refactor-era bug classes + prevention rules (cache-fill offset corruption, stale-.o masking non-compiling tree, run-without-x, test-all-callers); full doc in repo
- **remote_merge_2026_07_15** — Merged origin/main (thread-safe cache-fill + harness overhaul) — remote CI runs as ROOT so its harness code hides non-root bugs; fast suite green after fixes
- **rpm_container_build_fixes** — RPM container build (build-rpm-container.sh) history — io_uring/credential-plumbing bug chain, now stable; key host-vs-container build gotchas
- **rpm_packaging_three_packages** — RPM spec builds 3 packages (modules/client/tests) + two build bugs that only surface against EL stock nginx / dynamic modules
- **shared_code_consolidation** — shared/xrdproto code-sharing initiative collapsing src/<->client/ duplication — both audits fully closed, ~35 shared units, 60+ ngx-free symbols
- **shmtx_semaphore_lostwakeup** — Multi-worker connection-stall under concurrent load root-caused to ngx_shmtx POSIX-semaphore lost-wakeup; fixed by spin-only mode in shm_slots.c
- **split_files_three_build_systems** — Splitting a .c file that libxrdproto.a compiles requires updating shared/xrdproto/Makefile AND verifying the client build — the LD_PRELOAD shim whole-archives the lib and `make check` won't catch missing split objects
- **src_simplification_helpers** — Two new src/ boilerplate-reduction helpers (str-dup-z, webdav status-only response); config-merge-wrapper idea rejected by existing design
- **unified_brix_config_grammar** — 2026-07-06 unified config grammar LANDED — bare brix_* storage directives via http common module, hard rename (xrootd→brix_root, *_root→brix_export), 3-line cvmfs cache; evict_at/evict_to still have NO consumer (top follow-up)

### `history-client-tooling.md` — Client tooling

- **client_credfile_hardening** — client credential/temp-file reads must use xrdc_open_credfile / xrdc_credfile_bio / open_download_temp (symlink+owner+perm safe)
- **client_fast_fail_permanent_errors** — native client must fail FAST on permanent errors (DNS NXDOMAIN, redirect loop, TLS-required-on-cleartext, handshake rejection) — not retry them
- **client_feature_gap_program** — 2026-07-06 client feature-gap program LANDED on main — 20 tasks, all user-facing tool gaps closed; gotchas for future client work
- **client_firewall_resilience** — native-client FUSE hardening vs a misbehaving inline firewall (handshake timeout, retry backoff, fire-and-forget endsess); verified vs official xrootd 5.9.5 through fault proxy; + conda codec-lib build gotcha
- **client_ipv6_v4_downgrade** — native-client IPv6→IPv4 sticky auto-downgrade for dual-stack hosts with broken IPv6 (FUSE + all libxrdc clients)
- **client_mount_speed_optim** — xrootdfs/xrdfs mount-speed optimization — parallel + lazy data streams, getaddrinfo/username micro-wins, GSI rtag localized
- **client_vfs_seam_guard** — Client-side VFS seam closure + guard extension (copy_web_upload + xrdfs up/download migrated, check_vfs_seam.sh now covers client/)
- **cvmfs_brix_client_plan** — brix Mount Platform — CVMFS-brix FUSE client + XRootDFS-brix + shared cvmfs core; all 7 sub-projects (A-G) landed, live-proven vs real atlas/cms/lhcb.cern.ch
- **cvmfs_docker_demo** — CentOS9-Stream cvmfs demo container (3128/3129/3130 + guard + fail2ban) — build/run gotchas and smoke proof
- **fuse_http_transport** — xrootdfs (single multi-call binary, async default) mounts over http(s)/WebDAV as well as root://; binaries live in client/bin/
- **oak_olmx_integration** — OAK CI + opencode codebase-index both point at the local OLMx OpenAI-compatible model server; config gotchas
- **phase49_client_code_sharing** — Phase-49 — share code across native CLI tools + the two FUSE drivers; headline workstreams (W0, W1, W2, W4-FUSE) DONE+tested 2026-06-21; lower-value W2/W3 tail deliberately deferred
- **phase69_client_concept_buckets** — 2026-07-04 client/ reorganized flat→src-style concept buckets (lib + apps)
- **pyxrootd_isolation_worker** — official XRootD/pyxrootd bindings run in an out-of-process worker, never imported into pytest itself
- **swiss_army_toolkit_vision** — Rob's standing directive to grow the native clients into a WLCG storage swiss-army-knife (keep official behaviour for compat, add tons of features) — North Star for all client work
- **xrdfs_cli_resilience_gap** — xrdfs CLI is not network-resilient; mgr+mfile is the parity path; dedicated loss-sweep harness exists
- **xrootdfs_async_rewrite** — Ground-up async/network-resilient xrootd-fuse3 rewrite (xrootdfs.c) + wire feature extensions — all 7 milestones DONE+validated

### `development-history.md` — Cross-cutting / index-level

- **admin_friendly_log_diagnostics** — XROOTD_DIAG helper + convention for admin-friendly error.log (cause/fix); which sites to convert vs leave
- **shared_xrdproto_coverage_guard** — shared/xrdproto is build-in-place; json_min added; check-shared-coverage.sh guards against stranded pure logic

### `history-protocols-and-feature-phases.md` — Protocols and feature phases

- **cms_real_protocol_wire_spec** — Exact XrdCms/YProtocol wire format for real-cmsd interop — reference spec + where the interop implementation lives
- **phase24_write_mirroring** — Phase-24 write mirroring (W1 stream metadata, W2 HTTP methods, W3 stream data writes) — all implemented+built; W3 e2e runtime validation was env-blocked
- **phase34_pmark_status** — Phase-34 SciTags packet marking (src/pmark/) — essentially COMPLETE across root/webdav/s3/TPC/echo, full -Werror build + live-verified metrics/firefly; only optional dashboard panel remains
- **phase6_status** — Phase 6 WebDAV helper consolidation — RESOLVED; generic xml_builder/http_response infra removed as obsolete (specialised helpers won)
- **proxy_mode_bugs** — Three proxy implementation bugs found and fixed while developing test_proxy_mode.py
- **proxy_splice_underdrain_stall** — xrootd_proxy zero-copy splice path stalls large reads (60s client timeout) when splice(socket->pipe) under-drains (WSL2); fixed with self-healing fallback to buffered recv. This was the REAL cause of flaky test_conformance_topologies.
- **writev_stock_framing_fix** — kXR_writev AND chkpoint/ckpXeq wire framing fixed to stock contract (dlen frames descriptors / embedded sub-header only, body streamed after); both CLOSED 2026-07-02

### `history-security-and-credentials.md` — Security and credentials

- **backend_write_proxy_requirement** — Why davs://+S3 writes to a remote xroot backend fail without a configured x509 proxy — architectural (origin auth), not conformance or a bug
- **cred_store_weak_symbol_linkage** — Client cred-store handlers are WEAK-linked — a tool that builds a store must force the handler .o into its link or auth silently breaks
- **gsi_signed_dh_server** — XrdSecgsi signed-DH (v>=10400) SERVER path — DONE, all 4 interop directions green; cipher-negotiation gotcha that breaks signed interop
- **nginx_filter_proxy_gotchas** — Three non-obvious nginx internals hit while building Phase 21 (header filter ordering, proxy hide_headers_hash SIGFPE, access-phase handler order)
- **phase65_bad_actor_guard** — Phase-65 generic bad-actor MITM guard fully implemented 2026-07-02 (14/14 tasks, committed to main)
- **phase8_status** — Phase 8 openat2 confinement — PARTIAL as of 2026-06-12 audit: Step A done (stream), Step B ~half, HTTP not started, Step C blocked; old resolve/confine stack still load-bearing across ~30 sites
- **resilience_pki_expiry_fix** — tests/resilience GSI failures (cert verification failed / GSI-not-ready) were a STALE EXPIRED PROXY — ensure_pki only checked file existence, not validity
- **srr_wlcg_endpoint** — src/srr/ — WLCG Storage Resource Reporting HTTP/JSON endpoint (xrootd_srr); the deliberate replacement for the XRootD UDP f/g-stream monitoring stack
- **webdav_proxy** — New feature: nginx WebDAV module can now proxy requests to a backend HTTP/HTTPS server
- **xrdacc_port** — Port of XRootD XrdAcc authorization into the nginx module (src/acc/) — versioned dual engine, all 3 protocols, full OS/NIS — ALL 9 MILESTONES DONE
- **xrdacc_residual_gaps** — XrdAcc port residual gaps (RA1–RC1) all closed+tested; create-vs-update semantics, authz_check logical+resolved paths, AOP/host-keyed auth-cache

### `history-storage-and-caching.md` — Storage and caching

- **backend_meta_parity_phase4_decision** — Rob's 2026-06-29 decision on backend metadata-parity Phases 3/4 — proxy is enough for remote root://, fold S3 xattr/setattr into shared sd_s3 driver instead
- **beneath_api_logical_path** — openat2 beneath API (xrootd_open_beneath/_stat_beneath/_mkdir_beneath) takes the LOGICAL root-relative path, never the root_canon-prefixed absolute path
- **brixmount_cvmfs_rw_overlay** — 2026-07-05 brixMount cvmfs-rw writable overlay LANDED (7 commits on main) — union core client/lib/fs/overlay, rw FUSE driver, CLI subcommands, all suites green
- **ceph_docker_harness** — Single-node Ceph RADOS test cluster in Docker (tests/ceph_harness.sh) + Docker-Desktop/WSL2 networking constraint + containerized build workflow
- **cephfs_rados_interop_spike** — CephFS-on-RADOS layout research, read-only cephfsro driver, and the bidirectional striper<->CephFS migration toolchain (redirect/copy/finalize/rollback) — DONE
- **composable_cache_config_ganesha** — Ganesha-style cache config (cache_store=physical FSAL, cache_root=advertised logical root); xrootd_root elimination; migrated all cache tests to the composable grammar; generic URL scheme unification
- **csi_perread_xmeta_reload_bottleneck** — Multi-threaded root:// read scaling bug — CSI verify reloaded the xmeta record per read; fixed by snapshot-at-open
- **csi_trust_fs_and_default_on** — 2026-07-02 xrootd_csi now DEFAULT ON + new xrootd_csi_trust_fs skips read-verify on self-checksumming fs; .xrdt not hidden from dirlist (open follow-up)
- **cvmfs_proxy_absorb_upstream_flakiness** — cvmfs proxy resilience — stall-detect + force-primary retry + RTT geo-answer + unified-origin; landed, tested
- **data_posix_backend_confinement** — Rob's invariant: ZERO data-plane POSIX outside src/fs/backend/. A-1 reverted; file staging is now a VFS↔VFS (backend↔backend) move. Remaining raw-POSIX sites listed.
- **phase26_slice_caching** — Phase-26 slice-granular caching — stream plane implemented+runtime-validated; HTTP plane N/A by design; metrics skipped
- **phase67_fs_tpc_subfolder_sort** — 2026-07-02 phase-67 — loose src/fs/ and src/tpc/ files sorted into vfs/ and gsi/+outbound/+engine/; p66_apply.py gained --map; gotchas (untracked files break git mv, stale RAW_ALLOW after moves)
- **phase68_cvmfs_site_cache_landed** — 2026-07-02/03: phase-68 cvmfs:// protocol plane landed on main + follow-on fixes (upstream-allowlist bug, per-upstream metrics, dashboard cvmfs panel) — key gotchas not in the doc
- **xrdstorascan_backend_tooling** — Backend-aware sysadmin tooling (xrdstorascan client + src/scan/ server engine) — Phases 1-4a shipped, Phase 4b (catalog enumeration) deferred

### `history-testing-and-incidents.md` — Testing, conformance, CI, incidents

- **conf_inplace_update_dataloss** — Two fixes that cleared ~250 conf-suite failures: worker-unique ports for the differential harness + a real in-place-update data-loss bug (resume staging zeroed unwritten bytes)
- **conformance_200_batch** — differential conformance batches vs stock xrootd (256 + 908 tests) — 14 server/client divergences fixed incl rm-recursive-delete data loss, cache-flush 4-byte-fhandle regression, kXR_mkpath|kXR_async parent-create rule
- **conformance_batch4_libxrdcl** — Conformance batch 4 (~1160 tests) via real libXrdCl bindings + gfal API contract; 9+ divergences fixed
- **conformance_test_fixes_jun24** — Triage+fix of ~59 reproducing suite failures — almost all were STALE TESTS (server conformant vs stock), not server bugs; one real server gap (qconfig version)
- **coverage_gap_audit** — Test-coverage-gap audit: 4 real source bugs found+fixed (JWT aud-array, WebDAV PUT partial-object, S3 UploadPartCopy broken+symlink-escape) + tests closing dark security/data paths
- **cpu_flamegraph_profiling** — How to make CPU flame graphs of the nginx-xrootd module under read/write load + the two run_load_test.sh gotchas fixed
- **evil_actor_v3_rounds_scaling** — evil_actor_v3 timeouts are client-side connection churn on WSL2, not a module bug; ROUNDS auto-scales down on constrained hosts
- **full_suite_run_2026_07_07** — 2026-07-07 full-suite run — failures were REAL peer regressions not flakiness; resilient start-all fix landed; how to run the suite under a live concurrent peer session
- **k8s_test_lab** — The k8s-tests/ minikube+Helm test lab — what's built, how it's driven, and the remaining follow-ons
- **load_test_root_gsi_comparison** — How to run the nginx-xrootd vs native-xrootd load/perf comparison; rebrand gaps + native TLS-data break
- **manager_mode_write_bugs** — Bugs fixed in manager_mode: kXR_stat, kXR_dirlist not redirected; write-gate fired before redirect for kXR_open
- **phase33_gsi_flake_diagnosis** — ROOT CAUSE of test_concurrent GSI flake = ENVIRONMENT COLLISION: tests/run_load_test.sh does rm -rf /tmp/xrd-test/pki + regenerate + restart on the SHARED fleet while pytest serves GSI from it. NOT a server bug, NOT a conftest race. Earlier diagnoses (incl. the workflow + critic) were measuring the sweep collision.
- **phase51_resilience_batch1** — Phase-51 cross-protocol resilience — first implementation batch (7 workstreams) landed + validated
- **prelogin_ping_gate** — Pre-login kXR_ping is REJECTED (stock parity) — server is correct; several test files had stale 'ping ok pre-login' assertions that were fixed, not the server
- **protocol_test_suite_p0** — 12-file P0 protocol conformance suite (root/cms/xrdhttp) — files, port map, run command, drop-in findings
- **readv_oversized_hang_fix** — kXR_readv element larger than readv_ior_max HUNG XrdCl (served short instead of rejecting); now rejects like stock. Plus chaos delayed-CMS start-order fix.
- **reboot_lockup_audit** — Audit + fixes for "workers/entries stuck after many reboots" — SHM dead-holder mutex stranding, cache-fill O_EXCL lock dead-owner stranding, libcurl origin stall timeout, rate-limit gauge leak — all fixed; clean bill on ABBA/blocking-under-lock across the SHM surface
- **remote_test_suite** — k8s-tests/remote-suite — running the real pytest suite from a client container against a remote brix server (pyxrootd); status COMPLETE 390/390 handled
- **stale_conformance_test_fixes_jun24b** — Batch of stale-test fixes (Jun 24): server was CORRECT on query/login/dashboard/fattr-recurse/native-ls; tests carried wrong expectations, verified differentially vs stock
- **test_fleet_startall_speed** — manage_test_servers.sh start-all was slow (104s cold); TCP-first readiness probe + backgrounded CMS mesh + parallel mesh wait_ready cut it to ~18s
- **test_harness_gotchas** — Test-harness operational gotchas — TEST_SKIP_SERVER_SETUP skips X509 setup, start-all exit codes, server warmup/resource exhaustion, orphan reaping, xdist parallel-safety
- **test_suite_fast_tier** — Fast iteration test tier (run_suite.sh --fast, ~4min) + slow-family auto-marker + fixed xdist collection-abort; perf findings behind the <5min PR-gate split
- **wlcg_token_conformance_suite** — WLCG bearer-token conformance suite — forge, 103 tests, 2 fixes; root:// validated robust; remaining phases scoped
- **wlcg_x509_500_conformance** — WLCG x509 500+ clause-indexed conformance suite + source-level XRootD v6.1.0 write-up (P0-P4)
- **wlcg_x509_conformance_landed** — WLCG x509/CA-dir conformance — signing_policy enforcement, proxy monotonicity, crl_mode, 3-layer suite + differential
