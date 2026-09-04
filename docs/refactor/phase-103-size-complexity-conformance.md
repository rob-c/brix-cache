# Phase 103 — Whole-project size & complexity conformance burndown

**Date:** 2026-08-09 (measured at `99eff8bd` + working tree)
**Source:** operator request — burn the file-size (>600 LoC) and function-complexity
(CCN>15) backlog across the *whole* project: the Python test suite and every
C/C++ source and header under `src/`, `client/`, and `shared/` — and leave the
gates positioned so it stays burned.
**Status:** HISTORICAL BURNDOWN, CURRENT GATES RESTORED (reconciled 2026-09-02).
The execution ledger records the genuine zero-debt close on 2026-08-11. The
current native and Python size/CCN gates and the Python Cognitive/NPath gate
were restored on 2026-09-02. See
`phase-111-repository-work-burndown.md` B111-002–005 for exact names. The plan
text below preserves the `99eff8bd` baseline; it is not the current census.
**Prerequisite reading:** `docs/refactor/phase-38-file-size-unix-modularity.md`
(the framework this phase completes), `docs/09-developer-guide/coding-standards.md`
§1/§8/§9, `CLAUDE.md` HARD BLOCKS.

---

## Table of contents

1. [Goal & non-goals](#1-goal--non-goals)
2. [The two conformance metrics, precisely](#2-the-two-conformance-metrics-precisely)
3. [Current measured state — the full inventory](#3-current-measured-state--the-full-inventory)
4. [Guard-coverage gaps — why "done" could rot](#4-guard-coverage-gaps--why-done-could-rot)
5. [The blocking prerequisite: `tests/userns/e2e_redteam` is inert](#5-the-blocking-prerequisite-testsusernse2e_redteam-is-inert)
6. [Wave plan](#6-wave-plan)
7. [Decomposition recipes](#7-decomposition-recipes)
8. [Tooling & guard changes in detail](#8-tooling--guard-changes-in-detail)
9. [Ordering, dependencies & risk](#9-ordering-dependencies--risk)
10. [Verification — per PR and per wave](#10-verification--per-pr-and-per-wave)
11. [Exit criteria (phase gate)](#11-exit-criteria-phase-gate)
12. [Appendix A — measurement commands](#appendix-a--measurement-commands)
13. [Appendix B — full function inventories](#appendix-b--full-function-inventories)

---

## 1. Goal & non-goals

**Goal.** At phase close, every in-scope file is ≤ 600 LoC, every in-scope
function is ≤ CCN 15, **and every ratchet that enforces those two facts scans
the entire project**, so the property is self-maintaining. Concretely:

- `tools/ci/file_size_backlog.txt` — empty, with the scan widened to
  `shared/`, `client/tests/`, and `*.cpp`/`*.cc`.
- `tools/ci/complexity_backlog.txt` — empty (today: 52 frozen functions), with
  the lizard scan widened to `shared/` and the C test harness trees.
- A Python complexity gate that does not exist today — blocking, with an
  empty backlog, over `tests/`, `cmdscripts/`, `utils/`, `tools/`.
- `cmdscripts/lint_loc.py` — hard cap ratcheted 800 → 600, `tests/loc_baseline.txt`
  still empty at the lower cap.
- The `tests/userns/e2e_redteam` suite **actually executing** — its repair is a
  hard prerequisite for roughly half the Python work (§5).

**Non-goals — explicitly out of scope:**

- **No behavior changes.** Every source change in this phase is a pure
  refactor; the verification bar is "the suite is byte-for-byte green before
  and after" (phase-38 §8), plus probe-count parity for test batteries (§10).
- Other quality ratchets (todo/fixme, vfs-seam, CodeChecker, -fanalyzer, dead
  code, duplication) — already gated; not this phase.
- `site/`, `docs/`, generated trees (`build/`, `.rpmbuild/`, `objs/`),
  worktrees (`.claude/worktrees/`), `bind-exploit.bak/` (dead backup), and the
  tracked shadow copy `k8s-tests/remote-suite/` (a synced mirror of `tests/` —
  carries `_SHADOW_MARKER`; it must stay *excluded* from every scan, see §4).
- `tools/xrd_fuzzer/` file sizes (4 files at 670–1475 raw LoC) — outside the
  operator's named scope; recorded as a **stretch tier** in §6 W7 so the
  decision is deliberate, not forgotten.

---

## 2. The two conformance metrics, precisely

The project already has two size regimes and one complexity regime. This phase
does not invent metrics; it finishes and unifies the existing ones.

### 2.1 File size

| Regime | Files | Metric | Cap | Enforced by | State |
|---|---|---|---|---|---|
| C/C++ | `src/`, `client/` `*.c`/`*.h` | **raw** `wc -l` (newline count) | 600 | `tools/ci/check_file_size.py` (blocking, `guards.yml`) | backlog **empty** ✅ |
| Python + shell | `tests/`, `utils/`, `k8s-tests/` per `lint_loc.in_scope()` | **logical** LoC (non-blank, non-C-comment) | HARD 800 + tier report | `cmdscripts/lint_loc.py --strict` (blocking, `loc.yml`) | baseline empty, `must=0 should=1 watch=21` |

Target state: **both caps at 600**, scans widened per §4. "Logical LoC" for
Python keeps lint_loc's definition, with one fix: its `COMMENT_RE` strips
blanks and C-style comments but **not** Python `#` comments, so today a comment
line counts against a Python file. W0 aligns the metric (`^\s*#` added) —
a file must never be splittable by deleting its comments. Re-measure after
that change; the §3 numbers are under the current (stricter) metric, so the
real backlog can only be equal or smaller.

Escape hatches that already exist and stay: the `loc-lint: … exempt` magic
comment (first 40 lines, for generated/table files), and phase-38 §2.6's
directive-table (`ngx_command_t[]`) carve-out on the C side.

### 2.2 Function complexity

One metric everywhere: **lizard McCabe CCN, cap 15** (`tools/readability.py`
is the single lizard front-end; `readability.CCN_MAX = 15`).

| Regime | Scanned today | Gate | State |
|---|---|---|---|
| C (`-l c`) | `src/`, `client/` only | `tools/ci/check_complexity.py` (blocking) | 52 frozen entries, no new offenders ✅ |
| C in `shared/`, `tests/` C harnesses, `client/tests/` | **nothing** | none | 26 + 30 + 0 over cap (§3) |
| Python (`-l python`) | **nothing** | none | 140 over cap (§3) |

Target state: `check_complexity.py` covers `src/ client/ shared/` + the C test
trees with an **empty** backlog; a new sibling gate covers Python with an
**empty** backlog. Decomposition target when touching a function is **CCN ≤ 12**,
not 15 — leaving headroom so an honest one-branch bugfix later doesn't trip
the gate (precedent: the 2026-08-09 wave `1e86223a` decomposed to ~10–12).

---

## 3. Current measured state — the full inventory

Grand totals: **9 oversized files** (8 Python logical + 1 shipped C++ raw) and
**248 over-complex functions** (52 C frozen + 26 `shared/` + 30 tests-C + 140
Python). Full per-function lists are in Appendix B; this section is the
per-cluster view the waves are built from.

### 3.1 File size — C/C++

- `src/` + `client/` `*.c`/`*.h`: **0 over 600** (backlog file is empty).
- `shared/` (88 `.c`/`.h` files): **0 over 600** — clean but unguarded.
- `client/tests/` (guard carve-out): **0 over 600**.
- **The `.cpp` blind spot:** the guard globs `*.c`/`*.h` only. Shipped C++
  exists and one file is far over cap:

| File | Raw LoC | Status |
|---|---|---|
| `client/apps/ceph/xrdceph_striper_migrate.cpp` | **1092** | ❌ split (W4) — the only oversized source file in the shipped tree |
| `client/apps/ceph/xrdceph_cephfs_to_striper.cpp` | 552 | ✅ under cap; enters watch tier |
| `client/apps/ceph/pymigrate/shim/rados_manifest_shim.cpp` | 81 | ✅ |
| `tests/ssi_client.cc` | 126 | ✅ |
| `tests/ceph/*.cpp` (5 files) | ≤ 185 | ✅ |

`xrdceph_striper_migrate.cpp` is well-factored internally (28 functions, all
CCN ≤ 15) — it is purely a *file* split: §7 R5 proposes the seam
(probe/estimate reporting ~250 LoC, migrate/rollback/finalize engine ~350 LoC,
namespace+xattr+verify helpers ~300 LoC, CLI/main remainder).

### 3.2 File size — Python (logical LoC, current metric)

8 files over 600; 7 of them are in the **inert** userns suite (§5) and must
not be touched before the W1 repair:

| Logical LoC | File | Wave |
|---|---|---|
| 721 | `tests/userns/e2e_redteam_part38.py` (single 690-line function) | W2 |
| 634 | `tests/userns/e2e_redteam_part39.py` | W2 |
| 631 | `tests/userns/e2e_redteam_part46.py` | W2 |
| 630 | `utils/xrd_sec_probe.py` | W3 |
| 629 | `tests/userns/e2e_redteam_part42.py` | W2 |
| 618 | `tests/userns/e2e_redteam_part37.py` | W2 |
| 613 | `tests/userns/e2e_redteam_part11.py` | W2 |
| 606 | `tests/userns/e2e_redteam_part10.py` | W2 |

Context: lint_loc tier report today reads `total=3644 ideal=3622 watch=21
should=1 must=0`; 14 further files sit at 501–600 (conformant under a 600 cap;
they stay on the watch/don't-grow list). `tests/loc_baseline.txt` is empty —
nothing exceeds the current HARD 800.

Note: by **raw** count, `tests/test_audit_fixes_2026_08_09.py` is 694 lines
but ≤ 600 logical — conformant under the Python metric; listed here so nobody
"re-finds" it with `wc -l`.

### 3.3 Complexity — the 52 frozen `src/`+`client/` functions (CCN 16–22)

Already gated (may only shrink); this phase burns them to zero (W6). By
subsystem, with the shared recipe from §7:

| Cluster | Count | CCN range | Members (worst first) | Recipe |
|---|---|---|---|---|
| `fs/backend/pblock` | 13 | 16–22 | `pblock_open_existing` 22, `sd_pblock_close` 21, `sd_pblock_rename` 20, `sd_pblock_staged_commit` 20, `pblock_ident_resolve` 18, `pblock_catalog_open` 17, `sd_pblock_setattr_cred` 17, `pblock_refs_break_share` 16, `pblock_snap_valid_name` 16, `pblock_write_blocks` 16, `sd_pblock_ftruncate` 16, `sd_pblock_pwrite` 16, `sd_pblock_staged_open_as` 16 | R3/R4 |
| `core/` (compat, config, seccomp) | 5 | 19–22 | `brix_seccomp_core_apply` 22, `brix_server_setup_tls` 21, `brix_wverify_update` 20, `brix_tier_register_stores` 20, `brix_kxr_from_errno` 19 | R4 (errno map → table) |
| `auth/` | 5 | 16–21 | `brix_gssapi_srv_step` 21, `brix_imp_worker_deescalate` 21, `brix_imp_broker_drop_caps` 19, `pwd_parse_line` 17, `brix_failsafe_get_crl` 16 | R3 |
| `fs/backend/cache` | 4 | 16–19 | `cache_fill_pump` 19, `brix_sd_cache_demote` 19, `meta_check_manifest` 18, `sd_cache_verify_manifest` 16 | R3 |
| `protocols/gridftp` | 4 | 17–18 | `ev_do_pasv` 18, `brix_ftp_ev_process` 17, `brix_ftp_ev_eb_accept` 17, `brix_ftp_build_gsi` 17 | R3 |
| `protocols/root` | 4 | 16–20 | `brix_handle_clone` 20, `brix_open_resolved_file` 17, `brix_open_map_open_error` 16, `mv_execute` 16 | R4 |
| `client/` | 4 | 17–20 | `brix_mpxstats_main` 20, `brix_wait41_main` 18, `brixautofs_valid_fqrn` 17, `brix_tls_read` 17 | R2/R4 |
| fs misc (`vfs`, `cache/origin`, `xfer`) | 4 | 16–21 | `brix_vfs_writer_open` 21, `brix_vfs_rename` 17, `brix_cache_origin_query_checksum` 17, `brix_baq_reconcile` 16 | R3 |
| `protocols/webdav` | 3 | 16–21 | `webdav_conf_pick_ca_file` 21, `webdav_validate_auth_paths` 16, `webdav_digest_value_hex` 16 | R4 |
| `net/` (guard, ratelimit) | 3 | 16–17 | `guard_classify_handshake` 17, `brix_rl_key_stream` 16, `rl_key_http_derive` 16 | R4 |
| `fs/backend/s3` | 2 | 18–21 | `sd_s3_pread` 21, `sd_s3_pwrite` 18 | R3 |
| `tpc/` | 1 | 19 | `tpc_verify_source_checksum` 19 | R4 |

### 3.4 Complexity — `shared/` (26 over, CCN 16–34, ungated)

Two distinct populations:

**Shipped code (16 functions)** — real maintenance surface, wave W4:
`cvmfs_whitelist_parse` 29, `cvmfs_client_getxattr` 25, `cas_pack.c::replay`
25, `cvmfs_pathidx_write` 24, `cvmfs_classify_url` 23, `cvmfs_pathidx_open`
21, `client.c::load_trust_and_catalog` 21, `brix_proxy_connect_tunnel` 20,
`publish/fsck.c::fk_check` 20, `brix_cas_put` 20, `cas_pack.c::adopt_tail` 20,
`brix_cas_reap` 18, `cvmfs_publish_run` 17, `brix_cas_pack_put` 17,
`cvmfs_client_read` 16, `_cas_pack_part2.c::read_verified_fd` 16.

**Unit-test drivers (10 functions)** — `main`/battery shapes in
`*_unittest.c`: `walk_unittest.c::main` 34, `bundle_unittest.c::main` 23,
`catalog_write_unittest.c::read_back` 21 + `::build` 16,
`client_unittest.c::main` 19, `xorf_unittest.c::main` 18,
`cas_store_unittest.c::main` 17, `pathidx_unittest.c::test_roundtrip` 16,
`dict_unittest.c::main` 16, `catalog_unittest.c::main` 16. Recipe R2 —
mechanical.

### 3.5 Complexity — C/C++ test harnesses under `tests/` (30 over, CCN 16–51, ungated)

Almost entirely `main()` batteries; recipe R2 throughout. Clusters:
`tests/ceph/` (9: three CCN 45–51 live-test mains, five 21–32 striper/spike
mains, `striper_seed.c::main` 16), `tests/c/` (13, CCN 16–49:
`zip_fuzz_test` 49, `deleg_gate_test` 40, `nonutf8_codec_harness` 25,
`codec_edge_test::test_lookups` 23, `krb5_forward_live` 22+20, `aio_resil` 21,
`idmap_collapse_test` 19, `x509_oracle` 18, `test_csi_scrub` 18,
`gai_shim::getaddrinfo` 18, `sd_s3_meta_smoke` 17, `codec_test::run_codec`
16), `tests/userns/c/` (4: `userns_broker_test` 25+22, `creds_guard_test` 21,
`userns_exec_launcher` 20), `tests/unit/` (2: `test_xml_compat` 18,
`test_json` 18), `tests/tools/` (1: `pblock_meta_bench` 20).
`client/tests/` measures **clean** (159 functions, 0 over).

### 3.6 Complexity — Python (140 over, CCN 16–127)

**Cluster A — the inert userns red-team suite: 73 functions** (§5 blocks this).
Every one is a `run_*` battery: a linear sequence of independent probes sharing
`ok()`/`fail()` counters. The tail is extreme — 9 functions at CCN ≥ 100,
topped by `run_combo_idmap_edge_full_matrix` at **CCN 127 / 571 lines**. Full
list in Appendix B.2; recipe R1 converts each battery into a probe table with
driver CCN ~3.

**Cluster B — `tests/cmdscripts/` live-suite drivers: 31 functions** (CCN
16–40, worst: `pblock_live_part2.py::pblock_meta_gsi` 40,
`user_backend_cred_part2.py::base` 36, `operator_runtime_part2.py::run_suite`
34, `operator_runtime_part4.py::run_valgrind` 32,
`user_backend_cred_part3.py::root` 31). Same battery shape as Cluster A —
recipe R1.

**Cluster C — test helpers, conftest, fixtures: ~29 functions** (CCN 16–39,
worst: `_xrdcl_worker.py::_encode_response` 39,
`_test_evil_actor_v3_helpers_b.py::srv` 33, `load_test_part2.py::build_suites`
27). Mixed shapes: encoders/dispatchers → table dispatch (R4), server-fixture
builders → extract per-protocol setup helpers (R3).

**Cluster D — infrastructure & tools: 7 functions**:
`tests/fleet_declares.py::analyze_source` 22,
`tests/conftest_part3.py::pytest_collection_modifyitems` 18,
`tests/conftest_part5.py::pytest_collection_finish` 16,
`tests/.ubuntu-triage.py::main` 20, `utils/xrd_ref_server.py::handle` 20,
`utils/make_token.py::main` 16, and — pleasingly — the ruler itself,
`tools/readability.py::main` 18 (fixed in W0 while adding the language
parameter; the measuring tool should not fail its own measurement).

---

## 4. Guard-coverage gaps — why "done" could rot

Every gap below is a place where a regression lands silently today. Closing
them is as much the phase as the burndown is:

| # | Gap | Evidence | Fix (wave) |
|---|---|---|---|
| G1 | `check_file_size.py` never scans `shared/` | 88 clean files, zero enforcement | widen scan roots (W4 flip) |
| G2 | `check_file_size.py` globs `.c/.h` only — `.cpp`/`.cc` invisible | `xrdceph_striper_migrate.cpp` at 1092 | add extensions (W4 flip, after the split) |
| G3 | `check_file_size.py` carves out `client/tests/` | currently clean (0 over, 0 over-CCN) | fold in at W4 flip — free while clean |
| G4 | `check_complexity.py` scans `src/ client/` only | 26 `shared/` + 30 tests-C offenders unseen | widen after burn (W4/W5 flips) |
| G5 | No Python complexity gate at all | 140 offenders unseen | new gate, advisory W0 → blocking W7 |
| G6 | lint_loc HARD=800, tiers watch≤650/should≤800 | 8 files >600 are "legal" today | ratchet to 600 (W7) |
| G7 | lint_loc scope misses repo-root `cmdscripts/` and `tools/` `*.py` | fleet manager + fuzzer unmeasured | add `cmdscripts/*.py` (W0); `tools/` = stretch decision (W7) |
| G8 | lint_loc's `k8s-tests/*.sh` pathspec matches into `k8s-tests/remote-suite/` — the tracked shadow mirror of `tests/` — double-counting copies | `_SHADOW_MARKER` present | exclude `remote-suite/` explicitly (W0) |
| G9 | lint_loc `COMMENT_RE` doesn't strip Python `#` comments | comments count as logical LoC | align metric (W0) |

**The one sequencing rule that governs every flip:**
`tools/ci/check_ratchet_monotonic.py` enforces that ratchet backlogs *never
grow* — including gaining entries when a scan widens. So scope extensions must
land with a **zero-entry delta**: burn the cluster first, flip the gate after
(details §8.5). The single tolerated exception is seeding `file_size_backlog`
with `xrdceph_striper_migrate.cpp` if W4's split lags the flip — and the
recommended plan avoids even that by splitting first.

---

## 5. The blocking prerequisite: `tests/userns/e2e_redteam` is inert

Phase-38 §7.7 documents this in full; the short form, because half the Python
backlog sits behind it:

The 78-file suite (`e2e_redteam.py` + `_part2..part77`) **does not run**:
import dies at `e2e_redteam_part3.py:111` (`NameError: _KXR_OPEN_READ`), 31
names (the raw-kXR wire layer, CRC64-NVME helpers, several probe helpers) were
dropped by the mechanical split and exist nowhere, and the `import *` fan-out
cannot share `ok`/`fail`/`mint`/`http` globals across shards anyway. The
pytest wrapper's `assert "ALL PASSED" in run.stdout` is the only thing between
this and silent green.

**Consequence for this phase:** the 73 Cluster-A functions and the 7 oversized
userns files are *frozen* until the §7.7 repair lands (W1):

1. Restore the 31 dropped definitions from `f4804763:tests/userns/e2e_redteam.py`.
2. Replace the `import *` fan-out with `tests/split_continuation.py`'s
   `split_continuation.load(globals(), __file__, …)` so all 78 files execute
   into one namespace (this also makes part77's `__main__` guard fire).
3. Static audit → 0 unresolvable names; then a live run of the userns wrapper
   on a host with `newuidmap` + `/etc/subuid`.
4. Only then re-tier and decompose (W2).

Decomposing a battery in a suite that cannot run would be unverifiable — the
exact "worse than a long file" failure phase-38 §7.5 warned about and §7.7
then documented happening.

---

## 6. Wave plan

Each wave is independently landable, each ends green, and no wave leaves a
gate weaker than it found it. PR counts are estimates for review-sized chunks.

### W0 — Metric & tooling groundwork (no source-code moves) — ~2 PRs

1. `cmdscripts/lint_loc.py`: add `^\s*#` to `COMMENT_RE` (G9); add
   `cmdscripts/*.py` to `in_scope()` (G7); exclude `k8s-tests/remote-suite/`
   (G8). Re-run the tier report; publish the delta as an update note in this
   doc (the §3.2 list can only shrink).
2. `tools/readability.py`: `run_lizard(lizard, paths, lang="c")` — language
   parameter; decompose its own `main` (CCN 18 → ≤12) in the same PR.
3. New **advisory** Python complexity report: `readability.py --gate-csv
   --lang python tests cmdscripts utils tools` wired as a *report-only* CI
   step (pattern: `coverage.yml`'s `continue-on-error`). It becomes blocking
   only in W7, with an empty backlog — the backlog-never-grows invariant stays
   absolute (§8.5).
4. Guard unit tests: extend `tests/test_ci_guards.py` for every behavior
   changed above (lint_loc comment stripping, scope, exclusion; readability
   lang param).

### W1 — userns suite repair (prerequisite, blocking W2) — 1 PR + 1 live-run evidence note

Exactly §5 / phase-38 §7.7 steps 1–3. Pure repair — **no decomposition, no
re-splitting** in this PR, so the diff is reviewable as "restore + rewire".
Exit: static audit 0 unresolved; wrapper prints `ALL PASSED` on a
`newuidmap`-capable host; the probe count printed by the summary is recorded
in the PR description as the **parity baseline** for all of W2.

### W2 — userns burndown: 73 functions + 7 oversized files — ~8–12 PRs

The largest wave. Recipe R1 on every `run_*` battery, hardest-first (the nine
CCN ≥ 100 monsters pay the most maintenance rent). Per battery:

1. Slice the linear probe sequence into `_probe_<name>(ctx)` functions
   (each ≤ CCN 12, ideally one logical assertion cluster per probe).
2. Drive them from a module-level tuple; the `run_*` shell keeps its name and
   its ok/fail contract so the wrapper and summary are untouched.
3. **Probe-count parity is the acceptance test:** the wrapper's final counts
   must equal the W1 baseline exactly, per part-file. A decomposition that
   changes the number of executed checks is a bug in the decomposition.
4. File size falls out for free: once a battery is a probe table, the 7
   oversized shards split along probe-group lines via `split_continuation`
   (the shared-namespace idiom is already the suite's structure post-W1).

Optional (recommended, separate final PR): re-shard the suite from
"mechanical 600-line cuts" (`_partN`) to **one battery per file** named after
the battery — file boundaries are free under `split_continuation`, and
`part38.py` stops being a number and becomes
`redteam_symlink_crossproto_toctou.py`. Do this only after all batteries are
decomposed, as a pure `git mv`-shaped shuffle (OP approval for git write ops
per HARD BLOCKS).

Grouping: ~8 PRs of ~9 batteries each, grouped by theme (DAC/group, S3,
WebDAV, raw-kXR/protocol, combo_*, broker/limits, TPC/lifecycle, remainder).

### W3 — Python rest: 67 functions + `utils/xrd_sec_probe.py` — ~6–8 PRs

- **Cluster B (cmdscripts, 31):** R1, identical shape to W2 but each driver is
  verified by running that cmdscript live (they are runnable suites; TESTING.md
  documents the fleet). One PR per cmdscript family (`operator_runtime*`,
  `user_backend_cred*`, `cvmfs_*`, `cache_*`, singles).
- **Cluster C (helpers, ~29):** R3/R4 per shape; verify by running the pytest
  modules that import each helper (grep-driven closure per PR).
- **Cluster D (7):** conftest collection hooks → extract per-marker predicates;
  `fleet_declares.analyze_source` → per-declaration-kind scanners;
  `xrd_ref_server.handle` → opcode dispatch table; `make_token.main` /
  `.ubuntu-triage.py::main` → argparse + per-command functions.
- **`utils/xrd_sec_probe.py` (630 logical):** R5 — split probe batteries from
  CLI/reporting; lint_loc already scans `utils/*.py` so the win registers
  immediately.

### W4 — `shared/` C + the C++ blind spot — ~3–4 PRs, then two gate flips

1. 16 shipped functions (§3.4) via R3/R4 — `whitelist_parse` 29 and
   `client_getxattr` 25 first. `shared/` code is consumed by both the module
   and the client: **full clean rebuild** of both after any header move
   (mixed-ABI gotcha), and any new `.c` file must be registered in
   `client/Makefile` (`check_client_build_coverage.py`) and, if the module
   compiles it, repo-root `./config` (`check_config_coverage.py`).
2. 10 unittest drivers via R2.
3. `xrdceph_striper_migrate.cpp` 1092 → 3–4 TUs along the §3.1 seam.
4. **Flip A (size):** widen `check_file_size.py` to `shared/`,
   `client/tests/`, and `*.cpp`/`*.cc` — zero new entries by construction.
5. **Flip B (complexity):** add `shared` to the gate's scan roots — zero new
   entries by construction.

### W5 — C test harnesses under `tests/` — ~2–3 PRs, then a gate flip

30 functions via R2 (`main` battery → `static int test_*()` + run table).
The three ceph live-test mains (CCN 45–51) need a live Ceph target only to
*run*; decomposition is verified by compile + unchanged check inventory, with
a live run where the lab exists (they are live-lab tools, not CI suites).
Then **Flip C:** add the C test trees (`tests/c`, `tests/ceph`,
`tests/userns/c`, `tests/unit`, `tests/tools`, `client/tests`) to
`check_complexity.py` — zero new entries.

### W6 — the frozen 52 — ~4–6 PRs

Burn `complexity_backlog.txt` to empty, cluster-by-cluster per the §3.3 table
(pblock alone is a PR or two). Precedent `1e86223a` cleared 16 in one wave
with the same recipes; the remaining 52 are the same CCN 16–22 tail. Where a
decomposition creates a genuinely reusable seam, add targeted unit tests
(same precedent: "2 new test suites"); otherwise phase-38 §8 byte-for-byte
verification carries the wave. New TUs → `./config` / `client/Makefile`
registration.

### W7 — Ratchet endgame — 1–2 PRs

1. lint_loc: tiers become `ideal ≤500 / watch ≤600`, `HARD = 600`; `--strict`
   green with `tests/loc_baseline.txt` still empty (everything >600 is gone by
   now); `must`/`should` tiers retired or redefined as >600.
2. Python complexity gate flips **blocking** with an empty backlog; register
   the backlog file in `check_ratchet_monotonic.py` and `tests/test_ci_guards.py`;
   add to `guards.yml`.
3. Stretch decision, recorded either way: `tools/xrd_fuzzer/` sizes
   (`generators.py` 1475, `lifecycle.py` 1005, `webdav.py` 714,
   `strategies.py` 670) — either split under the same recipes or mark
   `loc-lint: exempt` with a reason line.
4. Close out: update `CLAUDE.md` / `agent-guide-extended.md` pointers (the
   "file-size MUST tier" language becomes "600 everywhere"), append the
   completion note to this doc, and leave a memory pointer per
   `record-findings-in-project-docs`.

---

## 7. Decomposition recipes

**R1 — Python battery → probe table.** Before: one `run_x()` with 40 inline
probe blocks sharing `ok()/fail()`. After: `_probe_*(ctx)` functions + a
`PROBES = (…)` tuple + a ~5-line driver loop in `run_x()`. Driver CCN ~3;
probes ≤12 each. Contract preserved exactly: same probe order, same counter
totals, same summary line. The probe functions take an explicit small context
(paths, sessions, minted tokens) instead of closing over 500 lines of locals —
which is precisely what makes them individually readable and re-runnable.

**R2 — C unittest `main` battery → test table.** `static int test_<case>(void)`
per case, `struct { const char *name; int (*fn)(void); }` table, `main` loops
and reports. Zero behavior change; the harness output format is preserved
where a wrapper greps it.

**R3 — parse/validate/state-machine extraction (shipped C).** The CCN 20–29
shapes in `shared/` and the module are parse loops and multi-phase
operations: extract per-record/per-field handlers (`parse_line` →
`parse_key()`, `parse_acl()`…), per-phase helpers
(`open → resolve/verify/commit`), and per-state handlers for state machines.
Rules carried from `CLAUDE.md`/coding-standards: early-return, no `goto`, use
the existing HELPERS (never re-derive path/auth/metrics/framing), errno→kXR
mapping stays table-driven, `static` helpers stay in-TU unless a second
caller exists.

**R4 — the CCN 16–19 one-extraction tail.** Most of the frozen 52 need exactly
one cut: hoist the validation prologue, or convert an if/else-if ladder to a
lookup table, or extract the error-mapping switch. Resist restructuring
beyond what the cut needs — these functions are otherwise mature.

**R5 — file splits.** Decide the idiom by `f29e4f86`'s one question — *do the
parts refer backwards to each other?* Independent parts → extracted modules
(+ thin facade keeping the import surface). Backward-referring parts (Python
test shards) → `split_continuation.load` shared-namespace shards. C → new TUs
along ownership seams + build registration. Never split mid-function; W2/W3
decompose functions first, then the file falls apart along natural lines.

---

## 8. Tooling & guard changes in detail

### 8.1 `tools/ci/check_file_size.py` (W4 flip)
Scan roots become `src/`, `client/` (dropping the `client/tests` carve-out),
`shared/`; suffixes become `.c .h .cpp .cc`. Keep raw-`wc -l` semantics and
CAP 600. `shared/xrdproto/` stays in (it is clean; if generated files land
there later, use the exemption comment, not a scan hole).

### 8.2 `tools/readability.py` (W0)
`run_lizard(lizard, paths, lang)`; `--lang {c,python}` on the CLI; decompose
its own `main`. All complexity tooling continues to flow through this single
engine so the gate and ad-hoc reports can never drift (existing design note in
`check_complexity.py` explains why).

### 8.3 `tools/ci/check_complexity.py` (flips at W4/W5)
Scan list `["src", "client"]` grows to `+["shared"]` (W4) then the C test
trees (W5). Each flip lands in the same PR as proof of zero delta
(`--regen` producing a byte-identical backlog).

### 8.4 New: `tools/ci/check_complexity_py.py` (advisory W0 → blocking W7)
Mirror of `check_complexity.py` with `lang="python"`, scan roots
`tests cmdscripts utils tools`, backlog `complexity_py_backlog.txt`. Advisory
lane from W0 (visibility during the burndown); blocking from W7 with an empty
backlog; registered in `check_ratchet_monotonic.py`, `tests/test_ci_guards.py`,
and `guards.yml` at flip time.

### 8.5 The no-growth sequencing invariant
`check_ratchet_monotonic.py` treats any backlog growth as failure — including
"honest" growth from a scope widening. This phase never fights that guard:
**every scope flip lands after its cluster is burned, with a provably empty
delta**, and the new Python backlog file is *born empty* at blocking time.
Nothing in this plan requires the guard-of-guards to grant an exception, which
is exactly why the plan is ordered the way it is.

### 8.6 `cmdscripts/lint_loc.py` (W0 + W7)
W0: metric fix (G9), scope add (G7), shadow-mirror exclusion (G8). W7:
`HARD = 600`, tier boundaries `ideal ≤500 / watch ≤600`. The baseline file
stays empty at both steps — the burndown precedes the ratchet.

---

## 9. Ordering, dependencies & risk

```text
W0 ──► W1 ──► W2 ─────────────┐
 │                            ├──► W7
 ├──► W3 (indep. of W1/W2)────┤
 ├──► W4 ──► flips A+B ───────┤
 ├──► W5 ──► flip  C ─────────┤
 └──► W6 (indep., any time)───┘
```

W3–W6 are mutually independent and can interleave with W2; W7 requires all of
them. Suggested serial order for a single operator: W0, W1, W6 (highest
shipped-code value, precedent-backed), W4, W5, W3, W2 (longest), W7.

| Risk | Mitigation |
|---|---|
| Touching userns before repair — work no lane can execute | W1 is a hard gate; W2 PRs cite the W1 parity baseline |
| A "refactor" silently changes behavior | phase-38 §8 byte-for-byte verification; probe-count parity for batteries; no behavior PRs mixed into refactor PRs |
| Header/struct moves across `src/`↔`shared/`↔`client/` with stale objects | full clean rebuild of module *and* client after any header move (mixed-ABI gotcha is documented history) |
| New TU not registered → silent link/coverage drift | `check_config_coverage.py` / `check_client_build_coverage.py` are blocking; register in the same commit |
| Scope flip grows a backlog → monotonic guard red | §8.5: burn first, flip after, empty delta proven by `--regen` |
| Decomposing the 9 CCN≥100 batteries introduces probe reordering | probe table preserves source order; parity check is per-part, not global |
| Timing-sensitive suites flake during verification runs (WSL2 host clock steps backwards) | run verification on a stable-clock host or rerun-thrice discipline (precedent: phase-102 did exactly this) |
| Concurrent sessions fighting over the build tree / test fleet during long waves | one wave in flight per tree; fleet via `cmdscripts.manage_test_servers` only |
| Linter/formatter corrupting files mid-wave | repair with Edit, never `git restore` (HARD BLOCK); stop after 2 identical failures and reassess |
| Grouped PRs too large to review | wave sizing above targets ≤ ~10 functions or one file-split per PR |

---

## 10. Verification — per PR and per wave

Every PR in this phase is a pure refactor, so verification is equivalence,
not new coverage:

1. **Build** (C waves): `make -j$(nproc)` incremental; re-`./configure` only
   when a source list changed; full clean rebuild when a header/struct moved;
   `objs/nginx -t`.
2. **Guards**: `python3 tools/ci/check_file_size.py`,
   `python3 tools/ci/check_complexity.py` (+ the Python report), `PYTHONPATH=tests
   python3 -m cmdscripts.lint_loc --strict`, `check_ratchet_monotonic.py`,
   coverage-registration guards. All green, backlogs monotonically smaller.
3. **Behavior**: the affected suites byte-for-byte green before/after
   (phase-38 §8 lists the exact loop); battery decompositions additionally
   prove **probe-count parity** against the recorded baseline; cmdscript
   drivers are re-run live. Timing-sensitive suites: three consecutive green
   runs (phase-102 precedent).
4. **Ratchet advance**: `--regen` in the same PR as the fix it accepts, diff
   showing only removals (or the flip's zero-delta proof).
5. Full-suite `pytest -v` at each wave close, not each PR (TESTING.md fleet
   lifecycle; wave-close is also when the ASan lane must be green).

---

## 11. Exit criteria (phase gate)

- [ ] `tools/ci/file_size_backlog.txt` empty; scan covers `src/ client/
      (incl. client/tests) shared/`, suffixes `.c .h .cpp .cc`; no in-scope
      file > 600 raw LoC.
- [ ] `tools/ci/complexity_backlog.txt` empty; scan covers `src/ client/
      shared/` + C test trees; no in-scope C/C++ function > CCN 15.
- [ ] `complexity_py_backlog.txt` exists, is registered (monotonic guard +
      guard tests + `guards.yml`), is **blocking**, and is empty; no Python
      function under `tests/ cmdscripts/ utils/ tools/` > CCN 15.
- [ ] `lint_loc --strict` green with `HARD = 600` and an empty
      `tests/loc_baseline.txt`; tier report shows `should=0 must=0` under the
      new boundaries; `cmdscripts/` in scope; `remote-suite/` excluded;
      Python `#` comments excluded from logical LoC.
- [ ] `tests/userns/e2e_redteam` demonstrably executes: static audit reports
      0 unresolvable names; wrapper run prints `ALL PASSED` with probe counts
      equal to the W1 baseline; every battery ≤ CCN 15.
- [ ] `tools/xrd_fuzzer/` decision recorded (split or exempt-with-reason).
- [ ] Zero behavior change across the phase: full suite green, ASan lane
      green, no test's assertion set weakened.
- [ ] This doc updated with a completion note per wave (phase-38 execution-
      status pattern); memory pointer left.

---

## Appendix A — measurement commands

```bash
# File size — C/C++ (raw), current guard view + the .cpp blind spot
python3 tools/ci/check_file_size.py
find shared client/tests -type f \( -name '*.c' -o -name '*.h' \) -exec wc -l {} + | awk '$1>600'
find src client shared -type f \( -name '*.cpp' -o -name '*.cc' \) -exec wc -l {} + | awk '$1>600'

# File size — Python/shell (logical), tier report + >600 list
PYTHONPATH=tests python3 -m cmdscripts.lint_loc            # from tests/: tier report
python3 - <<'EOF'
import sys; sys.path.insert(0, 'tests')
from cmdscripts import lint_loc
for loc, p in lint_loc.measurements():
    if loc > 600: print(loc, p)
EOF

# Complexity — C gate view (src+client) and the ungated trees
python3 tools/ci/check_complexity.py
PYTHONPATH=tools python3 -c "import readability as r; lz=r.find_lizard(); \
print(*sorted(((f['ccn'],f['file'],f['func']) for f in r.run_lizard(lz,['shared']) \
if f['ccn']>15), reverse=True), sep='\n')"

# Complexity — Python (no gate yet)
lizard --csv -l python tests cmdscripts utils tools/readability.py | \
  awk -F, '$2>15 {print $2, $7, $8}' | sort -rn
```

Measured 2026-08-09 at `99eff8bd` + working tree. Anyone re-running these
after W0's metric fix should expect the Python logical-LoC numbers to shrink
slightly (comment lines stop counting) and nothing else to move.

## Appendix B — full function inventories

### B.1 The 52 frozen `src/`+`client/` functions
The authoritative list *is* `tools/ci/complexity_backlog.txt` (52 rows,
`path::func<TAB>ccn`); §3.3 groups it by cluster. Burning it to zero is W6.

### B.2 Python Cluster A — `tests/userns/e2e_redteam` (73 functions; W2)

| CCN | Len | Function |
|---|---|---|
| 127 | 571 | `part45.py::run_combo_idmap_edge_full_matrix` |
| 114 | 593 | `part11.py::run_s3_multipart_adversarial` |
| 109 | 603 | `part39.py::run_combo_multipart_lock_identity` |
| 109 | 576 | `part10.py::run_webdav_method_state` |
| 108 | 592 | `part42.py::run_combo_encoding_group_targets` |
| 108 
---

## Execution status (2026-08-11)

First implementation wave against this plan. Everything below is landed in the
working tree and verified (full nginx rebuild, client build + unit tests,
targeted behaviour suites, and every size/complexity/coverage guard green).
No behaviour change — every source edit is a pure refactor per §1.

### Landed

**File size — the whole C/C++ dimension is at zero.**
`tools/ci/file_size_backlog.txt` is now **empty** (was 7 entries incl. the
`.cpp` blind spot). Each split holds every new TU ≤ 600 raw LoC and preserves
the public surface:

| File | Before → after | New siblings | Notes |
|---|---|---|---|
| `src/core/config/http_common.c` | 1140 → 381 | `http_directives_core.h` / `_auth.h` / `_ops.h` | directive table sliced into 3 `#include`d fragments (same idiom as `stream/directives_*.h`) |
| `src/core/config/shared_conf.h` | 747 → 457 | `shared_conf_merge.h` | `ngx_http_brix_shared_merge` (CCN 23→driver ~6) decomposed into 5 verbatim per-family helpers |
| `src/protocols/webdav/get.c` | 793 → 300 | `get_serve.c`, `get_directory.c`, `get_internal.h` | serve phases + §6.6 listing extracted; `get_serve_directory` CCN 19 → ≤12 (redirect/enumerate/footer helpers) |
| `client/apps/ceph/xrdceph_striper_migrate.cpp` | 1092 → 531 | `xrdceph_striper_engine.cpp`, `_estimate.cpp`, `_internal.hpp` | anon namespace → `stripermig`; engine + estimator lifted verbatim |
| `client/apps/fs/xrdfs_meta.c` | 961 → 460 | `xrdfs_meta_ls.c`, `xrdfs_meta_ns.c` | `do_stat` 19, `do_ls` 20, `do_locate` 17 decomposed in place |
| `client/apps/copy/xrdcp_parse.c` | 653 → 451 | `xrdcp_parse_validate.c` | flag-matrix (19) split into delete/continue checks; `basic` (19) → flag table; `manifest` (24) → manifest/rate/retry |
| `client/lib/brix_ops.h` | 647 → 414 | `brix_cksum_ops.h`, `brix_copy_ops.h` | umbrella header sliced at existing section seams |
| `src/core/config/server_conf_merge_security.c` | 603 → 304 | `server_conf_merge_storage.c` | a concurrent dev-tree edit crossed the cap mid-wave; split at the security↔storage seam |

New `.c` TUs registered in repo-root `./config` (`get_serve.c`,
`get_directory.c`) and `client/Makefile` (`xrdfs_meta_ls/_ns`,
`xrdcp_parse_validate`, the two striper TUs) — `check_config_coverage.py` /
`check_client_build_coverage.py` green.

**Complexity — W6 `src/` burndown well underway.** `admin_socket.c::admin_dispatch`
(CCN **42**, the worst offender in the whole tree) → a per-command handler set
behind a flat prefix dispatcher; the **entire `fs/backend/pblock` cluster**
(`pblock_open_existing` 32, `sd_pblock_staged_commit` 25, `sd_pblock_close` 20,
`sd_pblock_ftruncate` 20, `sd_pblock_rename` 20, `pblock_refs_break_share` 18,
`pblock_ident_resolve` 18, `pblock_catalog_open`/`_nsidx_arm`/`sd_pblock_setattr_cred`/
`pblock_arm_storage_features` 17, `sd_pblock_pwrite`/`pblock_write_blocks`/
`pblock_snap_valid_name`/`sd_pblock_staged_open_as` 16); the config cluster
(`brix_tier_register_cache_store` 27, `brix_tier_register_stores` 20,
`brix_server_setup_tls` 21 → shared per-leg helper); `error_mapping.c::brix_kxr_from_errno`
19 → a lookup table (R4); and the `net/ratelimit` key pair (16/16 → shared VOLUME
helper). `complexity_backlog.txt` C entries 67 → 45 (`src/`). Every batch built
clean (`objs/nginx -t` green) and regen'd.

**Complexity — the C/C++/header dimension is now at ZERO (final wave, 2026-08-11).**
The remaining `src/` tail was burned to nothing: the root read/query/write
cluster (`brix_read_try_offload` 18 / `brix_readv_try_offload` 20 /
`brix_pgread_try_offload` 18 → one shared `read_offload_secondary` inline;
`brix_handle_clone` 20, `brix_open_resolved_file` 21, `brix_open_map_open_error`
16, `brix_query_stats` 18, `brix_query_xattr` 18, `brix_handle_set` 17,
`mv_execute` 16); the gridftp cluster (`brix_ftp_ev_process` 17,
`brix_ftp_ev_eb_accept` 17, `brix_ftp_build_gsi` 17 → `ftp_gsi_build_host_ctx`,
`brix_ftp_merge_conf` 22 → `ftp_merge_adopt_common`); webdav
(`guard_classify_handshake` 17, `webdav_digest_value_hex` 16,
`webdav_conf_pick_ca_file` 21, `xrdhttp_rfc3230_q_millis` 21 → `q_value_millis`);
and TPC (`brix_tpc_registry_add` 18 → shared `tpc_scan_slots`,
`tpc_verify_source_checksum` 19 → `tpc_split_cksum_reply`). The two functions
previously **frozen behind the 600-LoC cap were unblocked by file splits** rather
than left as backlog debt: `src/fs/backend/pblock/pblock_pack.c` (591) split its
five low-level segment helpers into new `pblock_pack_seg.c` (+ `pblock_pack_internal.h`
seam), dropping it to 538 LoC with room to decompose `pblock_pack_admit` 23
(→ `pack_open_admit_seg` + `pack_write_record`) and `pack_read_record` 16
(→ `pack_hdr_check`); `client/lib/net/tls.c` (591) moved `brix_tls_peer_cert_info`
+ `peer_collect_sans` into new `tls_certinfo.c`, dropping it to 534 LoC with room
to decompose `brix_tls_read` 17 (→ `tls_read_want_io`). New TUs registered in
`./config` (`pblock_pack_seg.c`, reconfigured) and `client/Makefile`
(`tls_certinfo.c`). `complexity_backlog.txt` and `file_size_backlog.txt` both
regen to **0 entries**; full nginx rebuild + `make -C client` clean.

**Complexity — the entire `shared/` tree is burned (Workstream C complete).**
All 26 `shared/` functions taken to CCN ≤ 15: the 16 shipped-code offenders
(`whitelist.c::cvmfs_whitelist_parse` 29 → line-classifier helpers;
`_client_part2.c::cvmfs_client_getxattr` 25 → per-attribute resolvers;
`cas_pack.c::replay` 25 / `adopt_tail` 17 → per-record handlers;
`cvmfs_pathidx_write` 24 / `_open` 21, `cvmfs_classify_url` 23,
`client.c::load_trust_and_catalog` 21, `cas_store.c::brix_cas_put` 20 /
`brix_cas_reap` 18, `fsck.c::fk_check` 20, `brix_proxy_connect_tunnel` 20,
`cvmfs_publish_run` 17, `brix_cas_pack_put` 17, `cvmfs_client_read` 16,
`read_verified_fd` 16) plus the 10 `*_unittest.c` `main`/battery drivers
(R2 — split into `test_*` sections behind a fixture; each recompiled and
**re-run**, probe-count preserved: walk 28 checks, bundle OK, xorf 17,
catalog_write 39, client 25, cas_store 16, pathidx ALL PASS, dict OK,
catalog 11). `complexity_backlog.txt` 93 → **67**; `shared/` rows now **0**
(the gate already scanned `shared/`, so no flip was needed — this is the
Workstream-C burndown that empties it). `client/` build clean; the cvmfs
shared units verified by direct compile+run.

**Complexity — the entire `client/` cluster is burned.** 17 `client/`
functions taken to CCN ≤ 12 (the `xrdfs_meta`/`xrdcp_parse` decompositions
above, plus `xrdfs_attr.c::do_query`/`do_prepare`, `copy_l2l.c::brix_copy_local_to_local`,
`checksum.c::brix_cksum_fd`, `ops_file_pg.c::file_pgread_frames`,
`brixautofs.c::brixautofs_valid_fqrn`, `wait41.c::brix_wait41_main`,
`mpxstats.c::brix_mpxstats_main`) and `shared_conf.h::ngx_http_brix_shared_merge`
(23). `complexity_backlog.txt` working-tree count 109 → 93; `client/` rows now
**0**. (`tls.c::brix_tls_read` CCN 17 is now burned too — the final wave split
`tls_certinfo.c` out to make room and extracted `tls_read_want_io`; see the
final-wave note above.)

**W0 — metric tooling.** `cmdscripts/lint_loc.py`: G9 (Python `#` comments no
longer count as logical LoC — `COMMENT_RE` gained `^\s*#`) and G8 (the tracked
`k8s-tests/remote-suite/` shadow mirror is excluded from `in_scope()`, so its
155 synced `.sh` copies stop double-counting). Guard tests for both landed in
`tests/test_ci_guards.py` (`test_lint_loc_metric_strips_python_hash_comments`,
`test_lint_loc_excludes_the_remote_suite_shadow_mirror`). The post-fix tier
report reads `total=3604 ideal=3597 watch=7 should=0 must=0`.

### Remaining (unchanged from the plan)

- ~~**W6 — C/C++/header complexity**~~ — **DONE.** All `src/` + `client/` +
  `shared/` functions are ≤ CCN 15; `complexity_backlog.txt` is empty. The
  `tls.c` and `pblock_pack.c` splits closed the last frozen entries. The gate
  now holds the whole shipped C tree at zero.
- ~~**W4 — `shared/` C**~~ — **DONE** (all 26 burned; see Execution status).
  The `shared/` size scan was already widened; the file-size backlog is empty
  there too, so no size flip remains.
- **W5 — C test harnesses** under `tests/` + the `check_complexity.py` flip.
- **W2/W3 — Python complexity (138):** the 73 userns `run_*` batteries (coupled
  to the 7 userns file splits — decompose the battery, the shard splits along
  probe groups) plus the cmdscripts/helpers/infra clusters. The userns suite
  now imports and runs cleanly, so the W1 prerequisite is already satisfied.
- **W7 — ratchet endgame:** `lint_loc` HARD 800→600 + tier reboundary; the
  Python complexity gate flips blocking with an empty backlog; `tools/xrd_fuzzer/`
  size decision.

### Verification run

`make -j$(nproc)` (nginx, clean link) · `make -C client` + `make -C client test`
(all unit tests + man/completions guards PASS) · `pytest test_webdav_html_listing
test_webdav test_webdav_b test_webdav_maxdelay` (green) · `pytest test_conf_xrdfs
test_conf_xrdfs_b test_clientconf_xrdfs test_client_xrdfs_tools` (green) ·
`check_file_size` / `check_complexity` / `check_py_complexity` /
`check_py_file_size` / `check_config_coverage` / `check_client_build_coverage`
all green. Both C ratchets regen to **0 entries** and a new guard test —
`tests/test_ci_guards.py::test_c_ratchet_backlogs_are_empty` (parametrized over
`complexity_backlog.txt` + `file_size_backlog.txt`) — locks that at zero, so a
future re-freeze reddens instead of silently rotting the property.
