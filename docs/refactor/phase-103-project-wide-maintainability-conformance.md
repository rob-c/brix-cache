# Phase 103 — Project-wide maintainability conformance (file-size + complexity, every tree)

**Date:** 2026-08-09
**Status:** HISTORICAL BURNDOWN, CURRENT GATES RESTORED (reconciled 2026-09-02).
The later ledger correctly records that every native/Python backlog reached zero
on 2026-08-11; the introductory “burndowns remain” text was stale. New work has
since crossed and was returned below the native/Python size gates. Python CCN
and the higher-order Cognitive/NPath gate were also restored on 2026-09-02. The exact current inventory is in
`phase-111-repository-work-burndown.md` B111-002–005. Do not restore a backlog or
ratify exemptions: return each absolute gate to zero.

### Implementation progress (updated 2026-08-11)

- **Workstream E — Python complexity + file-size → BOTH ZERO (DONE).**
  `py_complexity_backlog.txt` **= 0 entries** and `py_file_size_backlog.txt` **= 0
  entries**; `check_py_complexity.py` and `check_py_file_size.py` both exit 0, and
  `check_ratchet_monotonic.py` is green. Every Python function under
  `tests/`+`utils/`+`tools/` is now ≤ CCN 15 and every `.py` ≤ 600 logical LoC.
  The `tests/` burndown covered all 61 `userns/e2e_redteam_part*` impersonation
  batteries (CCN 27–129) plus 15 non-userns functions, decomposed behavior-
  preservingly (each helper's params verified free of leaked locals; userns
  assembly-load and `pytest --collect-only` re-checked). Decomposition-driven
  growth of nine `e2e_redteam` shards past 600 lines was absorbed into two new
  lean continuation shards `userns/e2e_redteam_part78/79.py` (load range bumped to
  `range(2, 80)`); the two standalone oversized files were split via
  `xrd_sec_probe_part2.register_extra(...)` (helpers passed as params — no
  `__main__` circular import) and `_test_session_bind_helpers_b.py` (reexport-exec
  so pytest still collects the moved classes).

### Implementation progress (updated 2026-08-10)

- **Workstream A — guard coverage — DONE.** `check_file_size`/`check_complexity`
  extended to `src`+`client`+`shared` and (via `readability.run_lizard(lang=None)`)
  to `.cpp/.cc`; NEW `check_py_complexity.py` + `check_py_file_size.py` gate the
  Python trees (`tests`/`utils`/`tools`) at CCN 15 / 600 logical LoC. All four are
  registered in `check_ratchet_monotonic.py`, the pytest guard harness
  (`test_ci_guards.py`), and **`.github/workflows/guards.yml`** (the Python
  complexity twin sits in `guard_set.PREPUSH_SKIP`, like its C counterpart);
  `check_directive_registry.py` is likewise wired + made executable.
- **Workstream E (partial) — `tools/`+`utils/` Python complexity → ZERO.** All 16
  offenders in those two trees decomposed below CCN 15; `py_complexity_backlog.txt`
  shrank 154 → 138 (the remainder is the `tests/` set). Regression coverage for the
  decompositions lives in `tests/test_maintainability_tools.py` (16 tests: verdict
  helpers, both splitters, the reference-server protocol round-trip, token kinds).
- **Remaining:** Workstream B (52 `src`+`client` C), C (25 `shared` C), D (1 `.cpp`
  size split), and the `tests/` half of E (138 Python functions). **Blocked on the
  two §3 decisions** (test-`main()`/pytest-body exemption; `shared/xrdproto`
  carve-out) — those determine which of the `tests/` + `shared/` offenders are
  burned down vs. moved to a documented allowlist, so they must be ratified before
  that tranche starts.
**Predecessors:** [`phase-38-file-size-unix-modularity.md`](phase-38-file-size-unix-modularity.md)
(the file-size ratchet + the userns-inert finding in its §7.7); commit `1e86223a`
plus `tools/ci/complexity_backlog.txt` (the CCN-15 gate on `src/`+`client/` C).
This phase **finishes the job those started**: it extends the same two ratchets to
the trees they never covered, adds the one dimension that was never gated at all
(Python complexity), and burns the combined backlog to zero.

---

## 0. TL;DR — what "done" means

Every hand-written source file in the repository — `src/`, `client/`, `shared/`
(C and C++, source **and** headers), and the Python test/tooling trees — is:

1. **≤ 600 LoC** (the enforced cap; ~500 preferred, one concept per file), and
2. **≤ CCN 15 per function** (lizard's default "needs refactoring" line),

with **both properties ratcheted in CI so nothing new can regress**, and with the
grandfather backlogs emptied rather than merely frozen.

Today three of those four trees are only *partially* gated, one dimension (Python
complexity) is *not gated anywhere*, and the visible backlog is a subset of the
real one. The single most important fact in this plan, established by measurement
in §2, is:

> **The ratchets are green because their scope has holes, not because the code is
> clean.** `check_file_size.py` and `check_complexity.py` scan only `src/` and
> `client/`, and only files ending `.c`/`.h`. That silently excludes **every
> `.cpp`/`.cc` file** (a 1092-line client tool among them), **the entire
> `shared/` tree** (88 shipped C/C++ files, **25 functions over CCN 15**), and
> **all Python complexity** (**153 functions over CCN 15**). Burning down the
> visible backlog without closing these holes would produce a green board over an
> unconformant tree — the exact failure `check_ratchet_monotonic.py` exists to
> prevent, arrived at through *scope* instead of a bumped number.

So the work is ordered **close the holes first, then burn down** — never the
reverse, or the burndown has no gate to defend it afterward.

**The whole job in one frame:**

| Dimension | Tree | Offenders today | Gated today | Target |
|---|---|---:|:---:|---:|
| Complexity (CCN>15) | `src`+`client` C | 52 | ✅ frozen | 0 |
| Complexity (CCN>15) | `shared` C/C++ | 25 | ❌ | 0 (or ≤ ratified test-`main()` exemptions) |
| Complexity (CCN>15) | Python (all trees) | 153 | ❌ (no gate exists) | 0 (or ≤ ratified pytest-body exemptions) |
| Complexity (CCN>15) | `.cpp/.cc`, `client/tests` C | 0 | ⚠️ latent | 0, gated |
| Size (>600 LoC) | `src`+`client` `.c/.h` | 0 | ✅ frozen | 0 |
| Size (>600 raw) | `.cpp/.cc` (client) | 1 | ❌ | 0, gated |
| Size (>600 raw) | `shared` `.c/.h` | 0 | ❌ | 0, gated (latent) |
| Size (>600 logical) | Python (`tests`+`utils`) | 8 | ⚠️ 800-tier only | 0, at 600 tier |
| Size (>600 raw) | `tools/**.py` | 4 | ❌ (out of scope) | 0, gated |

Grand total of concrete burndown items: **230 over-complex functions** + **13
over-size files** (+ the userns-suite *repair*, which is a correctness fix that
happens to unblock 73 of those functions and 7 of those files).

---

## Table of contents

1. [Why these two metrics](#1-why-these-two-metrics)
2. [The measured current state](#2-the-measured-current-state)
   · [2.1 the three ratchets & exact scope](#21-the-three-existing-ratchets-and-their-exact-scope)
   · [2.2 size census](#22-file-size--the-complete--600-loc-census)
   · [2.3 complexity census — C](#23-complexity--the-complete-ccn--15-census-cc)
   · [2.4 complexity census — Python](#24-complexity--the-complete-ccn--15-census-python)
   · [2.5 the coverage-gap map](#25-the-coverage-gap-map-the-crux)
3. [What "conformant" means, precisely](#3-what-conformant-means-precisely)
4. [The decomposition playbook — 7 patterns, 3 worked examples](#4-the-decomposition-playbook)
5. [Workstream A — close the guard coverage gaps](#5-workstream-a--close-the-guard-coverage-gaps)
6. [Workstream B — `src/`+`client/` C burndown (52)](#6-workstream-b--src--client-c-burndown-the-52-frozen-entries)
7. [Workstream C — `shared/` C/C++ burndown (25)](#7-workstream-c--shared-cc-burndown-25)
8. [Workstream D — `.cpp/.cc` size split (1)](#8-workstream-d--cppcc-size-split-1-file)
9. [Workstream E — Python: repair, then burn down (153 + 8)](#9-workstream-e--python-repair-then-burn-down)
10. [Sequencing, waves, effort](#10-sequencing-waves-and-effort)
11. [Verification — the per-PR gate](#11-verification--the-per-pr-gate)
12. [Risks, non-goals, out-of-scope](#12-risks-non-goals-and-explicit-out-of-scope)
13. [Exit criteria (phase gate)](#13-exit-criteria-phase-gate)

---

## 1. Why these two metrics

Two properties dominate the long-run maintenance cost of this codebase, and both
were historically enforced *by eye in review* until phases 38 and 87 converted
them to red/green ratchets:

- **File length.** A file that holds one concept is diff-reviewable, greppable, and
  safe to change; a 1000-line file hides its seams so every change risks an
  unrelated one. Coding-standards §1 sets ~500 preferred / 600 hard.
- **Function complexity.** Cyclomatic complexity (CCN) counts independent paths
  through a function. Past ~15 a reader can no longer hold every branch in their
  head, tests can no longer plausibly cover every path, and defects hide in the
  combinatorial corners. Coding-standards §4/§8 sets CCN 15 — lizard's own default
  warning line.

What the existing ratchets do **not** yet give us is (a) *coverage of the whole
tree the user cares about* — the C++ `.cpp` files, the `shared/` library, the
Python tooling — and (b) *a zeroed backlog*, so "conformant" is the steady state
rather than "frozen at whatever we inherited." This phase delivers both. The user's
goal is explicit: the **whole** project — Python tests, and `client`/`src`/`shared`
C++ (source and headers) — conformant with low-maintenance practice, and staying
that way.

---

## 2. The measured current state

Tools used: `wc -l` (raw LoC); `cmdscripts.lint_loc` (logical LoC — blank +
pure-comment lines stripped); `tools/readability.py`'s lizard front-end
(`lizard --csv -l c|python`, `CCN_MAX = 15`). Every table is a full enumeration —
where a group is large the rows are grouped by owning subsystem, but no offender is
omitted.

### 2.1 The three existing ratchets and their exact scope

| Guard | Metric / cap | Files it scans | Backlog today |
|---|---|---|---|
| `tools/ci/check_file_size.py` | raw `wc -l`, **cap 600** | `src/**/*.{c,h}` + `client/**/*.{c,h}` **minus `client/tests/`** | **empty** (green) |
| `tools/ci/check_complexity.py` | lizard CCN, **cap 15** | `src` + `client` via `lizard -l c` | **52 entries** (frozen, green) |
| `cmdscripts.lint_loc` (`loc.yml`) | logical LoC, tiers ideal≤500 / watch≤650 / should≤800 / **hard 800** | git-tracked `src/*.{c,h}`, `client/*.{c,h}`, `tests/*.py`, `utils/*.py`, `tests/*.sh`, `k8s-tests/*.sh`, `utils/*.sh`; **excludes `shared/xrdproto/`** + magic-comment-exempt files | baseline empty; **1 SHOULD** (userns part38, 721) |

`check_ratchet_monotonic.py` guards all three backlogs so they can only shrink.
Two structural facts create every gap in §2.5:

- All three match **`.c`/`.h` only** — never `.cpp`/`.cc`.
- `check_file_size` and `check_complexity` scan **only `src` and `client`** — never
  `shared/`. `lint_loc` reaches Python only under `tests/` and `utils/`, and reaches
  no `shared/` or `tools/` code.

### 2.2 File size — the complete > 600 LoC census

The shipped C tree (`src/`+`client/` `.c/.h`) is **already clean** — zero files over
600 raw LoC (emptied in `f29e4f86`). `shared/` `.c/.h` is also clean on raw size
(largest `shared/cvmfs/publish/publish.c` = 578). Every remaining oversized file is
in a tree **no size guard currently enforces at 600**:

| # | File | Raw | Logical | Tree / why unguarded | Split target |
|---|---|---:|---:|---|---|
| 1 | `tools/xrd_fuzzer/generators.py` | 1475 | — | `tools/` — outside every scope | 3 units by generator family |
| 2 | `client/apps/ceph/xrdceph_striper_migrate.cpp` | 1092 | — | `.cpp` — suffix excluded | 3 TUs (§8) |
| 3 | `tools/xrd_fuzzer/lifecycle.py` | 1005 | — | `tools/` | 2 units (scenario groups) |
| 4 | `tests/userns/e2e_redteam_part38.py` | 767 | 721 | `tests/` — 1 SHOULD; **inert (§9.1)** | data-driven collapse |
| 5 | `utils/xrd_sec_probe.py` | 730 | 630 | `utils/` — `lint_loc` sees it but 630<800 | probe/report split |
| 6 | `tools/xrd_fuzzer/webdav.py` | 714 | — | `tools/` | request/verify split |
| 7 | `tests/test_audit_fixes_2026_08_09.py` | 694 | — | `tests/` — under 800 hard | by fixture group |
| 8 | `tests/userns/e2e_redteam_part46.py` | 691 | 634 | inert | data-driven collapse |
| 9 | `tests/userns/e2e_redteam_part39.py` | 683 | 631 | inert | " |
| 10 | `tools/xrd_fuzzer/strategies.py` | 670 | — | `tools/` | strategy-group split |
| 11 | `tests/userns/e2e_redteam_part11.py` | 673 | 613 | inert | " |
| 12 | `tests/userns/e2e_redteam_part42.py` | 672 | 629 | inert | " |
| 13 | `tests/userns/e2e_redteam_part10.py` | 656 | 606 | inert | " |
| — | `tests/userns/e2e_redteam_part{37,45,47,17,43,13,76,70}.py` | 609–655 | 442–618 | inert (watch tier) | " |
| — | `client/apps/ceph/xrdceph_cephfs_to_striper.cpp` | 552 | — | `.cpp` — already < 600 | leave (watch) |

**Real burndown files: 13** (items 1–13 above). The eight `part{37…}` entries are
already < 600 raw but ride along in the §9.1 userns collapse. `shared/` contributes
zero size items; the whole `shared/` workstream (§7) is complexity-only.

### 2.3 Complexity — the complete CCN > 15 census (C/C++)

77 functions total across `src`+`client`+`shared`. **52 are the frozen
`src`/`client` backlog** (Workstream B); **25 are the ungated `shared/` set**
(Workstream C). `len` = lizard function length in lines; `p` = parameter count;
the *pattern tag* keys the §4 playbook.

**`src/` + `client/` — the 52 (frozen; Workstream B), grouped by subsystem:**

| CCN | len | File::function | @lines | Pat |
|---:|---:|---|---|:--:|
| 22 | 60 | `src/fs/backend/pblock/sd_pblock_open.c::pblock_open_existing` | 203–262 | S |
| 21 | 83 | `src/fs/backend/pblock/sd_pblock_open.c::sd_pblock_close` | 423–505 | S |
| 20 | 111 | `src/fs/backend/pblock/sd_pblock_staged.c::sd_pblock_staged_commit` | 176–286 | S |
| 20 | 61 | `src/fs/backend/pblock/sd_pblock_namespace.c::sd_pblock_rename` | 375–435 | V |
| 18 | 45 | `src/fs/backend/pblock/sd_pblock_ident.c::pblock_ident_resolve` | 67–111 | V |
| 17 | 125 | `src/fs/backend/pblock/sd_pblock_catalog.c::pblock_catalog_open` | 276–400 | S |
| 17 | 44 | `src/fs/backend/pblock/sd_pblock_cred.c::sd_pblock_setattr_cred` | 272–315 | V |
| 16 | 61 | `src/fs/backend/pblock/sd_pblock_io.c::sd_pblock_pwrite` | 105–165 | G |
| 16 | 80 | `src/fs/backend/pblock/sd_pblock_io.c::sd_pblock_ftruncate` | 276–355 | G |
| 16 | 23 | `src/fs/backend/pblock/pblock_snap.c::pblock_snap_valid_name` | 65–87 | V |
| 16 | 82 | `src/fs/backend/pblock/pblock_refs.c::pblock_refs_break_share` | 317–398 | S |
| 16 | 54 | `src/fs/backend/pblock/pblock_store.c::pblock_write_blocks` | 230–283 | G |
| 16 | 65 | `src/fs/backend/pblock/sd_pblock_staged.c::sd_pblock_staged_open_as` | 78–142 | S |
| 21 | 106 | `src/fs/backend/s3/sd_s3.c::sd_s3_pread` | 101–206 | G |
| 18 | 61 | `src/fs/backend/s3/sd_s3_write.c::sd_s3_pwrite` | 395–455 | G |
| 19 | 80 | `src/fs/backend/cache/sd_cache_fill_demote.c::brix_sd_cache_demote` | 38–117 | S |
| 19 | 91 | `src/fs/backend/cache/sd_cache_fill.c::cache_fill_pump` | 215–305 | S |
| 18 | 100 | `src/fs/backend/cache/sd_cache_manifest.c::meta_check_manifest` | 176–275 | V |
| 16 | 61 | `src/fs/backend/cache/sd_cache_manifest.c::sd_cache_verify_manifest` | 282–342 | V |
| 21 | 75 | `src/fs/vfs/vfs_writer.c::brix_vfs_writer_open` | 75–149 | S |
| 17 | 115 | `src/fs/vfs/vfs_rename.c::brix_vfs_rename` | 69–183 | S |
| 16 | 51 | `src/fs/xfer/backend_async_queue.c::brix_baq_reconcile` | 438–488 | S |
| 17 | 90 | `src/fs/cache/origin_protocol.c::brix_cache_origin_query_checksum` | 226–315 | D |
| 22 | 107 | `src/core/seccomp/seccomp_core.c::brix_seccomp_core_apply` | 200–306 | G |
| 21 | 118 | `src/core/config/runtime_server_tls.c::brix_server_setup_tls` | 59–176 | C |
| 20 | 86 | `src/core/config/runtime_server_backend.c::brix_tier_register_stores` | 211–296 | C |
| 20 | 54 | `src/core/compat/wverify.c::brix_wverify_update` | 92–145 | S |
| 19 | 60 | `src/core/compat/error_mapping.c::brix_kxr_from_errno` | 35–94 | D |
| 21 | 77 | `src/auth/gssapi/gsi_mech.c::brix_gssapi_srv_step` | 398–474 | S |
| 21 | 107 | `src/auth/impersonate/lifecycle_worker.c::brix_imp_worker_deescalate` | 214–320 | G |
| 19 | 75 | `src/auth/impersonate/broker_creds.c::brix_imp_broker_drop_caps` | 206–280 | G |
| 17 | 58 | `src/auth/pwd/pwdfile.c::pwd_parse_line` | 90–147 | P |
| 16 | 70 | `src/auth/crypto/store_policy_store.c::brix_failsafe_get_crl` | 112–181 | S |
| 20 | 139 | `src/protocols/root/read/clone.c::brix_handle_clone` | 41–179 | S |
| 17 | 96 | `src/protocols/root/read/open_resolved_file.c::brix_open_resolved_file` | 271–366 | S |
| 16 | 58 | `src/protocols/root/read/open_resolved_file_open.c::brix_open_map_open_error` | 241–298 | D |
| 16 | 63 | `src/protocols/root/write/mv.c::mv_execute` | 280–342 | S |
| 21 | 77 | `src/protocols/webdav/module_directives_cert.c::webdav_conf_pick_ca_file` | 249–325 | V |
| 16 | 40 | `src/protocols/webdav/put_body_digest.c::webdav_digest_value_hex` | 72–111 | P |
| 18 | 96 | `src/protocols/gridftp/ev/ftp_ev_data.c::ev_do_pasv` | 48–143 | S |
| 17 | 91 | `src/protocols/gridftp/ev/ftp_ev_mode_e_recv.c::brix_ftp_ev_eb_accept` | 470–560 | S |
| 17 | 78 | `src/protocols/gridftp/ev/ftp_ev_io.c::brix_ftp_ev_process` | 115–192 | D |
| 17 | 97 | `src/protocols/gridftp/ftp_module_gsi.c::brix_ftp_build_gsi` | 38–134 | C |
| 17 | 42 | `src/net/guard/guard_classify.c::guard_classify_handshake` | 168–209 | D |
| 16 | 65 | `src/net/ratelimit/ratelimit_keys.c::brix_rl_key_stream` | 60–124 | D |
| 16 | 52 | `src/net/ratelimit/ratelimit_keys.c::rl_key_http_derive` | 176–227 | D |
| 19 | 117 | `src/tpc/outbound/source_stream.c::tpc_verify_source_checksum` | 413–529 | S |
| 20 | 91 | `client/apps/diag/mpxstats.c::brix_mpxstats_main` | 128–218 | M |
| 18 | 74 | `client/apps/diag/wait41.c::brix_wait41_main` | 24–97 | M |
| 17 | 75 | `client/lib/net/tls.c::brix_tls_read` | 84–158 | S |
| 17 | 23 | `client/apps/fs/brixautofs.c::brixautofs_valid_fqrn` | 37–59 | V |

*(50 rows shown; the two remaining frozen entries —
`sd_pblock_open.c::pblock_open_existing` is listed once above and the 52-count in
`complexity_backlog.txt` also carries `mpxstats`/`wait41` under `client/`; the
authoritative list is the backlog file itself, which §6 walks top-to-bottom.)*

**`shared/` — the 25 (ungated; Workstream C):**

| CCN | len | File::function | @lines | Kind | Pat |
|---:|---:|---|---|---|:--:|
| 34 | 198 | `shared/cvmfs/walk/walk_unittest.c::main` | 203–400 | test-`main()` | M/exempt? |
| 29 | 72 | `shared/cvmfs/signature/whitelist.c::cvmfs_whitelist_parse` | 50–121 | shipped | P |
| 25 | 55 | `shared/cache/cas_pack.c::replay` | 217–271 | shipped | S |
| 25 | 57 | `shared/cvmfs/client/_client_part2.c::cvmfs_client_getxattr` | 190–246 | shipped | D |
| 24 | 93 | `shared/cvmfs/index/pathidx.c::cvmfs_pathidx_write` | 109–201 | shipped | S |
| 23 | 47 | `shared/cvmfs/grammar/classify.c::cvmfs_classify_url` | 60–106 | shipped | P |
| 23 | 108 | `shared/cvmfs/bundle/bundle_unittest.c::main` | 33–140 | test-`main()` | M/exempt? |
| 21 | 82 | `shared/cvmfs/client/client.c::load_trust_and_catalog` | 265–346 | shipped | S |
| 21 | 56 | `shared/cvmfs/catalog/catalog_write_unittest.c::read_back` | 136–191 | test | B/exempt? |
| 21 | 44 | `shared/cvmfs/index/pathidx.c::cvmfs_pathidx_open` | 205–248 | shipped | S |
| 20 | 40 | `shared/cache/cas_pack.c::adopt_tail` | 276–315 | shipped | S |
| 20 | 41 | `shared/cache/cas_store.c::brix_cas_put` | 106–146 | shipped | S |
| 20 | 47 | `shared/cvmfs/publish/fsck.c::fk_check` | 209–255 | shipped | V |
| 20 | 46 | `shared/net/proxy_connect.c::brix_proxy_connect_tunnel` | 33–78 | shipped | S |
| 19 | 251 | `shared/cvmfs/client/client_unittest.c::main` | 98–348 | test-`main()` | M/exempt? |
| 18 | 55 | `shared/cache/cas_store.c::brix_cas_reap` | 220–274 | shipped | S |
| 18 | 98 | `shared/cvmfs/filter/xorf_unittest.c::main` | 38–135 | test-`main()` | M/exempt? |
| 17 | 85 | `shared/cache/cas_store_unittest.c::main` | 32–116 | test-`main()` | M/exempt? |
| 17 | 42 | `shared/cache/_cas_pack_part2.c::brix_cas_pack_put` | 47–88 | shipped | S |
| 17 | 43 | `shared/cvmfs/publish/publish.c::cvmfs_publish_run` | 536–578 | shipped | C |
| 16 | 29 | `shared/cache/_cas_pack_part2.c::read_verified_fd` | 91–119 | shipped | G |
| 16 | 43 | `shared/cvmfs/client/_client_part2.c::cvmfs_client_read` | 136–178 | shipped | S |
| 16 | 44 | `shared/cvmfs/catalog/catalog_unittest.c::main` | 124–167 | test-`main()` | M/exempt? |
| 16 | 65 | `shared/cvmfs/catalog/catalog_write_unittest.c::build` | 63–127 | test | B/exempt? |
| 16 | 96 | `shared/cvmfs/dict/dict_unittest.c::main` | 47–142 | test-`main()` | M/exempt? |
| 16 | 54 | `shared/cvmfs/index/pathidx_unittest.c::test_roundtrip` | 108–161 | test | B/exempt? |

Split: **15 shipped functions** (must decompose) + **10 `*_unittest.c`
`main()`/harness helpers** (candidate for the §3 test-`main()` exemption — a linear
driver with 40 asserts is high-CCN, zero-risk). `client/tests/` C (159 functions)
and shipped `.cpp/.cc` are already 0-over-cap.

### 2.4 Complexity — the complete CCN > 15 census (Python)

**153 functions**, split sharply into two populations:

- **73 in `tests/userns/e2e_redteam_part*.py`** — CCN up to **127** — the **inert
  suite** (§9.1). Every one currently executes nothing; **do not touch before the
  repair.** Full 73-row list lives in the scratch file `py_ccn.txt` (regenerate via
  §11.4); the top of it: `part45::run_combo_idmap_edge_full_matrix` 127,
  `part11::run_s3_multipart_adversarial` 114, `part39::run_combo_multipart_lock_identity`
  109, `part10::run_webdav_method_state` 109, `part42::run_combo_encoding_group_targets`
  108, `part13::run_broker_resource_limits` 108, `part46::run_combo_rare_opcodes` 106,
  `part33::run_dataplane_integrity` 106, `part9::run_root_protocol_depth` 101 …
  down to 16.

- **80 non-userns** — CCN 16–40 — the real burndown (§9.2), full enumeration below.
  These separate into **66 under `tests/`+`cmdscripts/`+`utils/`** and **14 under
  `tools/`** (which only enter scope once §5.3's gate includes `tools/`).

**The 80 non-userns Python offenders (complete), grouped:**

*`tests/cmdscripts/` — live-runner batteries (25):*
| CCN | len | File::function | Pat |
|---:|---:|---|:--:|
| 40 | 188 | `pblock_live_part2.py::pblock_meta_gsi` | B |
| 36 | 219 | `user_backend_cred_part2.py::base` | B |
| 34 | 132 | `operator_runtime_part2.py::run_suite` | B |
| 32 | 183 | `operator_runtime_part4.py::run_valgrind` | B |
| 31 | 290 | `user_backend_cred_part3.py::root` | B |
| 27 | 91 | `fwd_matrix_live_part3.py::_run_cell_a` | B |
| 27 | 67 | `frm_stagecmd.py::main` | M |
| 26 | 95 | `dashboard_vfs_browse.py::run_checks` | B |
| 25 | 105 | `operator_runtime_part2.py::run_load` | B |
| 24 | 269 | `nonutf8_codec_part2.py::build_vectors` | D |
| 22 | 171 | `tap_proxy_live_part2.py::proxy_env_live` | B |
| 21 | 84 | `cvmfs_live_ext.py::bench` | B |
| 20 | 152 | `user_backend_cred_part5.py::p2` | B |
| 20 | 122 | `delegation_twostep.py::run_checks` | B |
| 20 | 100 | `cvmfs_catalog_completeness.py::check_counters_markers` | V |
| 20 | 67 | `operator_runtime_part3.py::run_profile_load` | B |
| 20 | 65 | `fwd_matrix_live_part3.py::_run_cell_c` | B |
| 19 | 84 | `cvmfs_live_ext_part5.py::faultproxy_bench` | B |
| 19 | 75 | `cvmfs_catalog_completeness.py::check_identity` | V |
| 18 | 78 | `cache_watermark.py::run_checks` | B |
| 17 | 94 | `cvmfs_driver_units_part2.py::brixcvmfs_check` | B |
| 17 | 83 | `cache_stage_throttle.py::run_checks` | B |
| 17 | 82 | `cachestore_live.py::_sidecar_cell` | B |
| 16 | 163 | `cvmfs_live_ext_part2.py::reverse` | B |
| 16 | 122 | `cred_metrics.py::counters` | B |
| 16 | 101 | `client_features_part2.py::section_cksum_tree` | B |
| 16 | 99 | `cvmfs_writer_conformance.py::run_checks` | B |
| 16 | 94 | `dashboard_demo_live.py::demo` | B |
| 16 | 77 | `credential_wt_ztn.py::run_checks` | B |
| 16 | 48 | `operator_runtime.py::clean_test_fleet` | B |
| 16 | 43 | `brixcvmfs_live.py::_build_brixcvmfs` | C |

*`tests/` (non-cmdscripts) — helpers, mocks, encoders (24):*
| CCN | len | File::function | Pat |
|---:|---:|---|:--:|
| 39 | 100 | `_xrdcl_worker.py::_encode_response` | D |
| 33 | 175 | `_test_evil_actor_v3_helpers_b.py::srv` | B |
| 27 | 175 | `load_test_part2.py::build_suites` | D |
| 27 | 75 | `test_evil_actor_v3.py::test_b7_bind_teardown_aba` | B |
| 27 | 58 | `clientconf/divergence.py::assert_expectation` | V |
| 25 | 42 | `test_shm_slab_safety_lint.py::_strip_c_comments` | P |
| 24 | 102 | `cvmfs/mock_stratum1.py::do_GET` | D |
| 23 | 132 | `resilience/asan_tls_read_harness.py::main` | M |
| 22 | 127 | `fleet_declares.py::analyze_source` | P |
| 22 | 68 | `_test_cvmfs_conformance_fuse_refresh_failover_helpers.py::conf_mount` | B |
| 21 | 72 | `cvmfs/conformance_common.py::srv_instance` | C |
| 21 | 70 | `x509forge.py::make_eec` | C |
| 21 | 69 | `test_krb5_cache_origin_e2e.py::cache_origin` | B |
| 20 | 74 | `_test_cvmfs_conformance_fuse_refresh_failover_helpers.py::_make_handler.do_GET` | D |
| 20 | 54 | `.ubuntu-triage.py::main` | M |
| 19 | 63 | `_server_launcher_part2_mixinb.py::stop` | S |
| 18 | 82 | `conftest_part3.py::pytest_collection_modifyitems` | D |
| 18 | 63 | `test_fault_proxy_ctl_event.py::test_event_log_records_refuse_and_sever` | B |
| 17 | 178 | `test_tpc_gsi_outbound.py::gsi_tpc` | B |
| 17 | 164 | `test_tpc_delegation.py::gate` | B |
| 17 | 71 | `test_audit_fixes_2026_08_09.py::test_cold_clean_fill_is_purged_by_age` | B |
| 17 | 52 | `_test_metadata_stress_helpers.py::_paced_hammer.worker` | S |
| 17 | 39 | `_test_conf_dirlist_helpers.py::_parse_dstat` | P |
| 16 | 122 | `_test_conf_stattypes_helpers.py::_build_matrix` | D |

*`tests/` — remaining singletons (11): `cvmfs/failproxy.py::main.handle` 16 (D),
`_xrdcl_proxy_part2.py::_decode_response` 16 (D), `conftest_part5.py::pytest_collection_finish`
16 (D), `x509_matrix_differential.py::run` 16 (B), `test_krb5_xrootd_interop.py::xrootd_krb5`
16 (B), `test_cvmfs_global_cas.py::test_evict_gc_reaps_canonical_stream` 16 (B),
`test_cmd_storage_backend_schemes.py::test_storage_backend_schemes_flow` 16 (B),
`matrix_layer.py::supported` 16 (V), `_test_dropin_byte_for_byte_helpers.py::_error_family`
16 (V).*

*`utils/` (2): `xrd_ref_server.py::handle` 20 (D), `make_token.py::main` 16 (M).*

*`tools/` — enters scope with §5.3 (14): `xrd_fuzzer/lifecycle.py::scenario_file_close`
25, `ci/asan.py::main` 24, `refactor/p66_apply.py::do_step` 23,
`ci/run_fanalyzer.py::main` 23, `xrd_fuzzer/webdav.py::_send_https_request` 23,
`xrd_fuzzer/__main__.py::main` 21, `ci/run_codechecker.py::run` 19,
`ci/check_gridftp_interop_image.py::check` 18, `readability.py::main` 18,
`poc_process_dlen_overflow.py::run_poc` 17, `poc_chkpnt_dlen_injection.py::run_poc`
17, `ci/coverage.py::main` 16, `poc_xrootd_gsi_truncated_auth.py::main` 16,
`xrd_fuzzer/runner.py::run` 16.*

### 2.5 The coverage-gap map (the crux)

| Gap | Invisible today | Magnitude | Closed by |
|---|---|---|---|
| **G1** — `.cpp/.cc` never size-checked | `xrdceph_striper_migrate.cpp` 1092, `xrdceph_cephfs_to_striper.cpp` 552 | 1 real | §5.1 |
| **G2** — `shared/` never size-checked | 88 files, all < 600 today | 0 real, latent | §5.1 |
| **G3** — `shared/` never complexity-checked | 25 functions > CCN 15 | 25 | §5.2 |
| **G4** — `.cpp/.cc` never complexity-checked | 0 today | latent | §5.2 |
| **G5** — Python has **no** complexity gate | 153 functions > CCN 15 | 153 | §5.3 |
| **G6** — `tools/**.py` outside every size scope | 4 fuzzer files 670–1475 | 4 | §5.1 |

G1–G6 are why "the guards are green" and "the tree is conformant" are today two
different statements. Workstream A makes them one.

---

## 3. What "conformant" means, precisely

A file/function is **conformant** under this phase iff:

- **Size:** raw `wc -l` ≤ **600** for every hand-written `.c/.h/.cpp/.cc/.hpp/.hxx`
  under `src/`, `client/`, `shared/`; and logical LoC ≤ **600** for every
  hand-written `.py` under `tests/`, `cmdscripts/` (which lives at `tests/cmdscripts/`),
  `utils/`, `tools/`. Preferred target stays ~500 — 600 is the wall, not the aim.
- **Complexity:** lizard CCN ≤ **15** for every function in all the above trees, C
  and Python alike.
- **Exemptions** are explicit and few, declared exactly one of two ways, never by
  silence:
  - the existing `loc-lint: exempt` magic comment (generated directive tables,
    vendored spec headers), **or**
  - a first-class allowlist entry the relevant guard reads, carrying a one-line
    reason — mirroring how `check_file_size` documents its `client/tests/` carve-out.
- The **backlogs are empty** (bar ratified exemptions). A frozen entry is a
  deferral, not conformance; the phase gate (§13) is "zero entries."

**Two decisions this phase must ratify in the Workstream-A PR** (proposed defaults
in bold):

1. **Test-harness `main()` / pytest-body functions** — the 10 `shared/**/*_unittest.c`
   drivers (CCN 16–34), the C test `main()`s under `tests/`, and pytest test-body
   functions whose CCN is asserts-in-sequence not branching: **default = exempt from
   the CCN cap via an allowlisted `*_unittest.c` + `test_*.py::test_*` carve-out**,
   because a linear "setup → N asserts → teardown" driver is high-CCN / zero-risk;
   **but oversize test *files* are still split.** The `run_checks`/`build_suites`/
   `srv`/`base` battery *helpers* (not themselves `test_*`) are **not** exempt — they
   are §9.2 burndown. Draw the line at "is it a pytest test-item or an xUnit
   `main()`?" — yes → exempt; helper called by one → refactor.
2. **`shared/xrdproto/`** — the vendored wire spec, already `lint_loc`-exempt:
   **default = extend the same carve-out to both new guards.** It is not
   hand-written project code.

If decision 1 lands as "exempt", Workstream C shrinks from 25 → **15 shipped
functions** and the Python burndown from 80 → the non-`test_*`/non-`main` subset;
the exempted rows move to a documented allowlist, not the backlog.

---

## 4. The decomposition playbook

Every offender maps to one of seven recurring shapes. The pattern tag in §2.3–2.4
picks the technique; three are worked end-to-end below against *real* functions from
this tree so the method is concrete, not abstract. All techniques obey the
non-negotiables: **no `goto`; early-return; wire/ABI signatures fixed; INVARIANTS
1–12 (`CLAUDE.md`) preserved; each genuinely-new reachable behavior gets the
mandated 3 tests (success + error + security-negative)** — pure structural
extractions lean on the existing suite as the regression oracle.

| Tag | Shape | Technique | CCN effect |
|:--:|---|---|---|
| **G** | guard-clause / cleanup ladder — repeated `if (err){cleanup; return}` | extract a `do_one(...)`/cleanup helper; each site becomes one early-return | −1 per collapsed site |
| **D** | dispatch / type switch — long `if x==A … elif x==B …` | table/registry `{key: handler}`; body becomes `h=T.get(k); return h(...)` | collapses to ~3 |
| **P** | parse loop — one big `while` over tokens/lines with per-class branches | per-token-class handler funcs; loop just routes | −(#classes) |
| **S** | state machine — sequential phases sharing locals | extract each phase to a named helper taking an explicit state struct | −(#phases) |
| **V** | validation cascade — N field checks before the action | per-field validators returning a verdict; action after the gate | −(#fields) |
| **C** | config assembly — build a struct section by section | per-section builder helpers | −(#sections) |
| **B** | linear test battery — "do op → assert" ×N (Python/tests) | data-driven `CASES=[(op,expect),…]` + tiny runner | collapses to runner's own low CCN |
| **M** | `main()` driver | arg-parse / run / report split — or the §3 test-`main()` exemption | −, or exempt |

### 4.1 Worked example — Pattern **G**: `seccomp_core.c::brix_seccomp_core_apply` (CCN 22 → ≈6)

The complexity is almost entirely one shape repeated four times — add a table of
syscall rules, bailing out on the first failure:

```c
/* BEFORE — @200-306, four copies of this loop, each +N to CCN */
if (mode == BRIX_SECCOMP_CORE_ENFORCE) {
    for (i = 0; i < BRIX_SECCOMP_N(brix_seccomp_deny_hard); i++) {
        if (brix_seccomp_core_add(ctx, SCMP_ACT_KILL_PROCESS,
                                  brix_seccomp_deny_hard[i], err_fn, ud, &n_deny) != 0) {
            seccomp_release(ctx); return BRIX_SECCOMP_CORE_ERR;
        }
    }
    if (!allow_exec) { for (...) { /* deny_exec, same body */ } }
}
if (allow_exec)  { for (...) { /* allow deny_exec, same body */ } }
for (...)        { /* allow the base allow[] set, same body */ }
```

```c
/* AFTER — one helper carries the loop + the cleanup-on-fail; each site is one line */
static int add_rule_set(scmp_filter_ctx ctx, uint32_t act,
                        const int *tbl, unsigned n,
                        brix_seccomp_err_fn err_fn, void *ud, unsigned *counter) {
    for (unsigned i = 0; i < n; i++)
        if (brix_seccomp_core_add(ctx, act, tbl[i], err_fn, ud, counter) != 0)
            return -1;                 /* caller releases ctx */
    return 0;
}
/* body: */
if (mode == BRIX_SECCOMP_CORE_ENFORCE) {
    if (add_rule_set(ctx, SCMP_ACT_KILL_PROCESS, HARD, N_HARD, err_fn, ud, &n_deny)) goto fail_release;
    if (!allow_exec &&
        add_rule_set(ctx, SCMP_ACT_KILL_PROCESS, EXEC, N_EXEC, err_fn, ud, &n_deny)) goto fail_release;
}
```

`goto` is banned here — so `fail_release` becomes a single early-return guarded
helper `release_and_err(ctx, err_fn, ud, rc)` returning `BRIX_SECCOMP_CORE_ERR`, and
each site reads `if (add_rule_set(...)) return release_and_err(ctx, err_fn, ud, 0);`.
CCN drops from 22 to ≈6 with **no behavior change** — same rules, same order, same
release-on-fail. Oracle: the existing `test_seccomp_*`/userns suites.

### 4.2 Worked example — Pattern **P**: `whitelist.c::cvmfs_whitelist_parse` (CCN 29 → ≈8)

A single `while (i < marker)` loop classifies each line (E-expiry / line-0 ts /
N-repo / fingerprint) inline — every classifier branch adds to the one function's
CCN (@50-121):

```c
/* AFTER: the loop routes; each line-class is a named predicate+handler */
static int wl_is_expiry_line(const unsigned char *L, size_t n);   /* 'E'+14 digits  */
static int wl_is_repo_line  (const unsigned char *L, size_t n);   /* 'N'<fqrn>      */
static void wl_take_fingerprint(cvmfs_whitelist_t *o, const unsigned char *L, size_t n);

while (i < marker) {
    line_span(buf, marker, &i, &L, &n);           /* advance + slice one line */
    if      (wl_is_expiry_line(L, n)) e_expiry = wl_parse_expiry(L+1, n-1);
    else if (lineno == 0)             first_ts  = parse_expiry(L, n);
    else if (wl_is_repo_line(L, n))   wl_set_repo(out, L+1, n-1);
    else                              wl_take_fingerprint(out, L, n);
    lineno++;
}
/* the signed-body/hash/signature tail (@108-120) extracts to wl_bind_signature(out,buf,len,marker) */
```

The subtle E0–E9-fingerprint disambiguation (the bug the comment at @68-75
documents) moves *intact* into `wl_is_expiry_line` — one place, one test
(`test_cvmfs_whitelist_*`), instead of buried in a 72-line loop. CCN 29 → ≈8.

### 4.3 Worked example — Pattern **D**: `_xrdcl_worker.py::_encode_response` (CCN 39 → ≈6)

A cascade of `if tname == "XRootDStatus" … if tname == "StatInfo" …` type checks
(@135-…), each a branch:

```python
# AFTER: a registry keyed by type name; the cascade becomes a dict lookup
_ENCODERS = {
    "XRootDStatus":  lambda r: {"__status__": _encode_status(r)},
    "StatInfo":      _encode_statinfo,
    "StatInfoVFS":   _encode_statinfo_vfs,
    "DirectoryList": _encode_dirlist,
    "LocationInfo":  _encode_locinfo,
    # … one row per type, each body already exists verbatim as the branch payload
}
def _encode_response(resp):
    if resp is None:                                   return None
    if isinstance(resp, (bytes, bytearray, memoryview)): return _b64(resp)
    if isinstance(resp, (str, bool, int, float)):      return resp
    if isinstance(resp, tuple): return {"__tuple__": [_encode_response(x) for x in resp]}
    if isinstance(resp, list):  return {"__list__":  [_encode_response(x) for x in resp]}
    if isinstance(resp, dict):  return {"__dict__":  {str(k): _encode_response(v) for k,v in resp.items()}}
    enc = _ENCODERS.get(type(resp).__name__)
    return enc(resp) if enc else _encode_object_fallback(resp)
```

The container/scalar guards stay (they must precede the registry — see the @141-146
comment on why a bare `str` reached via a list must not hit the fallback). Each
`_encode_*` helper is the branch body lifted verbatim. CCN 39 → ≈6; new helpers are
individually unit-testable. Oracle: the `_xrdcl` proxy round-trip tests.

**Pattern B (the dominant Python shape, ~45 of the 80)** has no worked example here
because it is mechanical: a `run_checks`/battery function that is
`step(); assert; step(); assert; …` becomes `CASES = [(desc, thunk, expect), …]`
driven by `for d,t,e in CASES: _run_one(d,t,e)`. This *also* shrinks the file, so it
frequently resolves a size offender and a complexity offender in one edit — but for
the userns suite it is only sound **after** §9.1 gives the shards a shared namespace.

---

## 5. Workstream A — close the guard coverage gaps

**Lands first, as one reviewed infrastructure PR (or a tight cluster), before any
burndown.** It changes only guards + tests + backlogs — no source file moves. Its
backlogs are the *initial frozen snapshot* of everything §6–§9 then burns to zero.
Rationale: a burndown with no gate behind it silently rots; the gate must exist
first, so every subsequent PR ratchets.

### 5.1 Extend the size guards to `.cpp/.cc`, `shared/`, and `tools/` (G1, G2, G6)

`check_file_size.py` today (verified against its source):

```python
CAP = 600
# list_oversized(): for f in (root/"src").rglob("*): if f.suffix in (".c",".h") …
#                   for f in (root/"client").rglob("*"): … minus client/tests/
```

Changes:

```python
_SIZE_SUFFIXES = (".c", ".h", ".cpp", ".cc", ".hpp", ".hxx")
_ROOTS = ("src", "client", "shared")           # + shared
# carve-outs: client/tests/ (existing), shared/xrdproto/ (new, §3 decision 2)
```

- Regenerate the backlog: it captures **`xrdceph_striper_migrate.cpp` (1092)** as
  the sole real entry (§2.2 shows `shared/` ≤ 578 and `xrdceph_cephfs_to_striper.cpp`
  = 552 < 600). Everything else in the widened scope is already ≤ 600.
- **Python size** (pick one — decide in this PR, don't do both):
  - **Option A (recommended):** add `tools/**/*.py` to `lint_loc`'s pathspec and add
    a **600 logical-LoC ratchet tier for Python** beside the existing 800 hard tier,
    in a *separate* Python backlog so the C and Python walls don't entangle.
    `lint_loc` already owns Python size and logical LoC is the right metric there
    (docstrings/comments shouldn't count).
  - **Option B:** a dedicated `check_py_file_size.py` mirroring `check_file_size.py`.
    Simpler to reason about, one more guard to own. *Recommend A.*
- Register the new/changed guards in `check_ratchet_monotonic.py` (its `_BACKLOGS`
  list) so their fresh backlogs are one-directional from birth, and extend
  `tests/test_ci_guards.py` (it already has a parametrized guard test).

### 5.2 Extend `check_complexity.py` to `shared/` and `.cpp/.cc` (G3, G4)

`check_complexity.py` delegates to `readability.run_lizard(lizard, ["src","client"])`
with `-l c` pinned. Changes:

- `readability.run_lizard(lizard, ["src","client","shared"])`.
- Broaden the language pass so `.cpp/.cc` are analyzed. The `-l c` pin forces C
  parsing; either add a second `-l cpp` pass merged on `(file,func)` or drop the pin
  and let lizard auto-detect. **Pin a known-CCN fixture** in `test_ci_guards.py` so
  the analyzer's numbers can't silently move under a burndown (a C++ file whose
  functions have asserted CCNs).
- Apply §3 decision 1 to the 10 `*_unittest.c` `main()`s (exempt-list or backlog).
- `--regen`: the backlog grows from 52 to **52 + 15 shipped `shared/` functions**
  (+ up to 10 harness `main()`s if not exempted). This is a *deliberate, reviewed*
  widening — the one case `check_ratchet_monotonic` permits when scope legitimately
  grows; call it out in the PR body and allow it for exactly this commit.

### 5.3 Introduce the Python complexity gate (G5 — the missing dimension)

There is **no** Python CCN ratchet today. Add `tools/ci/check_py_complexity.py`,
structurally identical to `check_complexity.py`: import `readability`, run
`lizard -l python` over `tests cmdscripts utils tools`, cap 15, frozen backlog
`tools/ci/py_complexity_backlog.txt`, `--regen`, wired into
`check_ratchet_monotonic` + `test_ci_guards` + a CI lane (`loc.yml` is the natural
home).

- Initial backlog = the **153** functions from §2.4. Tag the **73 userns** rows
  `# blocked-on-phase-103-§9.1` so no one "simplifies" code that never runs.
- The 80 non-userns rows (66 in `tests`/`cmdscripts`/`utils`, 14 in `tools`) are the
  §9.2 burndown list.

**Deliverable of Workstream A:** four guards (two widened, two new) green against
freshly-regenerated backlogs that *fully* describe §2's census;
`check_ratchet_monotonic` + `test_ci_guards` updated; one CI lane runs them all.
After this PR the board is honestly red-in-waiting — every §6–§9 item is a tracked
entry with a gate that forbids adding more.

---

## 6. Workstream B — `src/`+`client/` C burndown (the 52 frozen entries)

Highest maintenance value: shipped module code, already gated, so each fix is a pure
`--regen`-down with the whole test suite as oracle. The authoritative list is
`tools/ci/complexity_backlog.txt` walked top-to-bottom; §2.3 reproduces it with line
numbers and pattern tags. Grouped into 7 PRs by owning subsystem:

| PR | Cluster | Entries (CCN, pattern) | Count | Oracle |
|--:|---|---|--:|---|
| B1 | pblock backend | `pblock_open_existing` 22·S, `sd_pblock_close` 21·S, `sd_pblock_staged_commit` 20·S, `sd_pblock_rename` 20·V, `sd_pblock_catalog_open` 17·S, `sd_pblock_setattr_cred` 17·V, `sd_pblock_pwrite`/`ftruncate` 16·G, `pblock_ident_resolve` 18·V, `pblock_refs_break_share` 16·S, `pblock_write_blocks` 16·G, `pblock_snap_valid_name` 16·V, `sd_pblock_staged_open_as` 16·S | 14 | `test_pblock_*`, `pblock-fsck` |
| B2 | protocols (root/webdav/gridftp) | `brix_handle_clone` 20·S, `brix_open_resolved_file` 17·S, `brix_open_map_open_error` 16·D, `mv_execute` 16·S, `webdav_conf_pick_ca_file` 21·V, `webdav_digest_value_hex` 16·P, `ev_do_pasv` 18·S, `brix_ftp_ev_eb_accept` 17·S, `brix_ftp_ev_process` 17·D, `brix_ftp_build_gsi` 17·C | 10 | `test_file_api`, `test_webdav_*`, `test_gridftp_*` |
| B3 | fs cache/vfs/xfer | `brix_vfs_writer_open` 21·S, `brix_vfs_rename` 17·S, `cache_fill_pump` 19·S, `brix_sd_cache_demote` 19·S, `meta_check_manifest` 18·V, `sd_cache_verify_manifest` 16·V, `brix_baq_reconcile` 16·S, `brix_cache_origin_query_checksum` 17·D | 8 | `test_cache_*`, `test_vfs_*` |
| B4 | s3 backend | `sd_s3_pread` 21·G, `sd_s3_pwrite` 18·G | 2 | `test_cmd_storage_backend_schemes`, s3 suites |
| B5 | core (config/compat/seccomp) | `brix_seccomp_core_apply` 22·G (§4.1), `brix_server_setup_tls` 21·C, `brix_tier_register_stores` 20·C, `brix_wverify_update` 20·S, `brix_kxr_from_errno` 19·D | 5 | `test_seccomp_*`, `nginx -t`, `test_config_*` |
| B6 | net / tpc / client-lib / diag | `brix_rl_key_stream`/`rl_key_http_derive` 16·D, `guard_classify_handshake` 17·D, `tpc_verify_source_checksum` 19·S, `brix_tls_read` 17·S, `brix_mpxstats_main` 20·M, `brix_wait41_main` 18·M, `brixautofs_valid_fqrn` 17·V | 8 | `test_ratelimit_*`, `test_tpc_*`, client unit |
| B7 | auth (do last — most security-sensitive) | `brix_gssapi_srv_step` 21·S, `brix_imp_worker_deescalate` 21·G, `brix_imp_broker_drop_caps` 19·G, `pwd_parse_line` 17·P, `brix_failsafe_get_crl` 16·S | 5 | `test_gsi_*`, `test_impersonate_*`, `test_pwd_*` |

**Per entry:** apply the §4 pattern for its tag; keep the signature; re-check the
INVARIANT that touches its area (B7 → sigver/GSI HMAC intact; B1/B3 → VFS-seam
INVARIANT 12; B5 → SHM/seccomp). Order: **B1, B2 first** (largest, most churn-prone),
**B7 last** (security — do it when the technique is warm). Each PR ends with
`check_complexity.py --regen` showing *only removals*.

---

## 7. Workstream C — `shared/` C/C++ burndown (25)

Reachable only **after** §5.2 puts `shared/` under the gate. Size is already
conformant, so this is **complexity-only**. Three PRs:

| PR | Cluster | Shipped entries (CCN, pattern) | Oracle |
|--:|---|---|---|
| C1 | CVMFS parsers | `cvmfs_whitelist_parse` 29·P (§4.2), `cvmfs_classify_url` 23·P, `cvmfs_pathidx_write` 24·S, `cvmfs_pathidx_open` 21·S, `cvmfs_client_getxattr` 25·D, `cvmfs_client_read` 16·S, `load_trust_and_catalog` 21·S, `fk_check` 20·V, `cvmfs_publish_run` 17·C | `shared/cvmfs/**/*_unittest.c`, `test_cvmfs_*` |
| C2 | CAS content store | `cas_pack.c::replay` 25·S, `adopt_tail` 20·S, `brix_cas_put` 20·S, `brix_cas_reap` 18·S, `brix_cas_pack_put` 17·S, `read_verified_fd` 16·G | `shared/cache/*_unittest.c`, `test_cvmfs_global_cas` |
| C3 | net + `*_unittest.c` disposition | `brix_proxy_connect_tunnel` 20·S; **decide** the 10 test-`main()`s (§3.1) — exempt-list or split-and-simplify | proxy tests; the unittests themselves |

The parsers are classic "one big switch over wire tokens" (§4.2) — decomposing them
*also* sharpens the fuzz surface (they feed the `tools/xrd_fuzzer` corpus). The CAS
state machines (`replay`/`adopt_tail`/`put`/`reap`) must be asserted byte-identical
before/after — CAS integrity + INVARIANT 12 (VFS seam) are non-negotiable; the
in-tree `*_unittest.c` are the oracle, run every PR. If §3.1 lands "exempt," C3's
test-`main()` work is a one-line allowlist entry per file, not a decomposition.

---

## 8. Workstream D — `.cpp/.cc` size split (1 file)

Once §5.1 makes it visible: **`client/apps/ceph/xrdceph_striper_migrate.cpp`
(1092 → three TUs, each ≤ 600).** The file is already function-clean (~35 well-named
free functions), so this is a **split along existing seams**, not a rewrite. Verified
function map and cut lines:

- **New header `client/apps/ceph/xrdceph_migrate.h`** — the shared vocabulary:
  `enum Mode` (@100), `struct Opts` (@102), `enum Result` (@269), `struct StriperLayout`
  (@291), `struct Probes` (@620), `struct SampleRun` (@644), the `g_*` extern globals,
  and prototypes for the engine + estimate entry points.
- **`xrdceph_migrate_engine.cpp` (≈ lines 99–598, ~500)** — utilities (`logline`,
  `now_s`, `split_stripe`, `build_source_index`, `progress_tick`, `adler32_buf`,
  `xattr_num`, `dest_path`, `mkparents`, `cephfs_adler32`, `detach_stubs`) + the
  migrate/rollback/finalize engine (`read_striper_layout`, `dry_account`,
  `create_namespace_entry`, `map_data_objects`, `carry_user_xattrs`, `verify_migrated`,
  `delete_source_objects`, `finish_migrate`, `migrate_one`@463, `rollback_one`@514,
  `finalize_one`@541).
- **`xrdceph_migrate_estimate.cpp` (≈ lines 599–808, ~210)** — `fmt_dur`@599,
  `fmt_rate_mib`@610, `probe_enumeration`@629, `sample_migrate`@664,
  `probe_read_bw`@713, `probe_pool_totals`@735, `scale_estimate`@749,
  `estimate_report`@767.
- **`xrdceph_striper_migrate.cpp` (remainder, ≈ lines 809–1092, ~280)** — arg parse +
  `usage`@922, `run_worker_pool`@989, `main`@1043.

**Wiring:** register the two new TUs in `client/Makefile` — INVARIANT: new `client/`
TUs go there and `check_client_build_coverage.py` enforces it. Rebuild the ceph
client, run its live/spike tests (`tests/ceph/*`). No function bodies change; the CCN
census stays 0-over-cap. `xrdceph_cephfs_to_striper.cpp` (552) is already conformant —
leave it on the watch list.

---

## 9. Workstream E — Python: repair, then burn down

### 9.1 Prerequisite — repair `tests/userns/e2e_redteam*` (BLOCKS 73 of 153 CCN + 7 of 13 size files)

Called out in [`phase-38 §7.7`](phase-38-file-size-unix-modularity.md) and the
standing memory `userns_e2e_redteam_suite_is_inert`: the 78-file suite **executes
nothing** — it dies at import (`NameError: _KXR_OPEN_READ` in a `def` default), 31
wire-layer names were dropped by the original mechanical split, and
`from …_partN import *` cannot feed shard globals, so 75 files reference names bound
only in another module. **Do not split, simplify, or extend any `e2e_redteam_part*`
file before this repair** — every such change is invisible to CI and therefore
unverifiable. Repair, verbatim from phase-38 §7.7:

1. Restore the 31 dropped definitions from
   `git show f4804763:tests/userns/e2e_redteam.py` into `e2e_redteam.py` (the raw-kXR
   layer `_kxr_connect`/`_kxr_send_recv`/`_kxr_session`/`_kxr_handshake_bytes`/
   `_kxr_login_bytes`/`_kxr_oneshot`/`_kxr_read_response`, the `_KXR_*` opcode/flag
   constants, `_crc64nvme`/`_crc64nvme_b64`, `_raw_get_header`, `_raw_get_validators`,
   `_s3_post_form`, `_dead_xattr_count`, `_dead_xattr_has_value`).
2. Replace every `from e2e_redteam_partN import *` with
   `split_continuation.load(globals(), __file__, …)` so all 78 files exec into **one**
   namespace (this also makes part77's `if __name__ == "__main__"` guard fire, since
   the exec'd shard inherits the entry script's `__name__`).
3. Re-run the static name audit (must report 0 unresolvable names), then the userns
   wrapper on a host with `newuidmap` + `/etc/subuid`.
4. **Only then** address size/complexity.

**Then the collapse (E4).** Every `run_combo_*` is a linear "do op → assert verdict"
battery — Pattern B at extreme scale (CCN up to 127). Hoist each into a table of
`(op, expectation)` cases driven by one shared runner; this collapses CCN to single
digits **and** shrinks the 7 oversize part-files in the same edit — but is only sound
once step 2 gives every shard the shared helper namespace. ~4 PRs, batched by scenario
family (idmap/combo, s3-multipart, webdav-method, group-dac).

### 9.2 The 80 non-userns Python offenders (not blocked on §9.1)

Burnable the moment §5.3's gate exists. Full enumeration in §2.4; grouped into PRs by
directory + pattern:

| PR | Group | Representative entries | Pat | Oracle |
|--:|---|---|:--:|---|
| E2a | cmdscripts live batteries (part 1) | `pblock_meta_gsi` 40, `user_backend_cred_part2::base` 36, `part3::root` 31, `part5::p2` 20 | B | the scripts' own `run_checks` / manage_test_servers |
| E2b | cmdscripts live batteries (part 2) | `operator_runtime_part2::run_suite` 34/`run_load` 25, `part4::run_valgrind` 32, `part3::run_profile_load` 20, `tap_proxy_live_part2::proxy_env_live` 22, `cvmfs_live_ext*::bench`/`faultproxy_bench`/`reverse` | B | " |
| E2c | cmdscripts checks/validators + fwd matrix | `fwd_matrix_live_part3::_run_cell_a/_c` 27/20, `delegation_twostep::run_checks` 20, `cvmfs_catalog_completeness::check_*` 20/19, `cache_*::run_checks`, `cred_metrics::counters`, `credential_wt_ztn::run_checks`, `cvmfs_writer_conformance::run_checks`, `client_features_part2::section_cksum_tree`, `dashboard_*` | B/V/C | " |
| E2d | encode/decode + mocks | `_xrdcl_worker::_encode_response` 39·D (§4.3), `nonutf8_codec_part2::build_vectors` 24·D, `load_test_part2::build_suites` 27·D, `mock_stratum1::do_GET` 24·D, `_make_handler.do_GET` 20·D, `failproxy::main.handle`/`_decode_response`/`conftest_part{3,5}` collection hooks·D, `_test_conf_stattypes_helpers::_build_matrix` 16·D | D | round-trip + conformance suites |
| E2e | parsers + test-helpers | `test_shm_slab_safety_lint::_strip_c_comments` 25·P, `fleet_declares::analyze_source` 22·P, `_parse_dstat` 17·P, `x509forge::make_eec`/`conformance_common::srv_instance`/`cvmfs/conformance_common` 21·C, `_server_launcher_part2_mixinb::stop` 19·S, `_paced_hammer.worker` 17·S | P/C/S | unit + fleet declares guard |
| E2f | tests that are pytest *test-bodies* | `test_evil_actor_v3::test_b7…` 27, `test_tpc_gsi_outbound::gsi_tpc` 17, `test_tpc_delegation::gate` 17, `test_krb5_*`, `test_cvmfs_global_cas::…`, `test_cmd_storage_backend_schemes::…`, `test_audit_fixes_2026_08_09::…`, `test_fault_proxy_ctl_event::…` | B/M | **candidate for §3.1 exemption** — decide before refactoring |
| E2g | utils + tools | `utils/xrd_ref_server::handle` 20·D, `utils/make_token::main` 16·M, `tools/xrd_fuzzer/*` (`scenario_file_close` 25, `_send_https_request` 23, `__main__::main` 21, `runner::run` 16), `tools/ci/*` (`asan::main` 24, `run_fanalyzer::main` 23, `run_codechecker::run` 19, `check_gridftp_interop_image::check` 18, `coverage::main` 16), `tools/refactor/p66_apply::do_step` 23, `tools/poc_*::run_poc/main` 17/16, `tools/readability::main` 18 | D/M/B | the tools' own smoke runs |

Each fix ends in `check_py_complexity.py --regen` shrinking its backlog. §3.1's
decision determines whether E2f is "refactor" or "allowlist"; resolve it in
Workstream A so E2f is unambiguous.

### 9.3 Python file-size burndown (the non-userns oversize files)

Once §5.1 Option A adds the 600 Python tier — 6 files (userns part-files handled in
E4):

| File | Raw | Split |
|---|---:|---|
| `tools/xrd_fuzzer/generators.py` | 1475 | 3 units by generator family (already class-structured) |
| `tools/xrd_fuzzer/lifecycle.py` | 1005 | 2 units by scenario group |
| `utils/xrd_sec_probe.py` | 730 | probe-core / report split |
| `tools/xrd_fuzzer/webdav.py` | 714 | request-build / verify split |
| `tests/test_audit_fixes_2026_08_09.py` | 694 | by fixture group (facade + helper module) |
| `tools/xrd_fuzzer/strategies.py` | 670 | strategy-group split |

The fuzzer files are the big lift but already module-structured (generators /
lifecycle / strategies / webdav), so each splits along its internal class/strategy
boundaries into ≤ 600-line units. Split test files with the "do the parts refer back
to each other?" question that governed the `f29e4f86` test-split wave (facade +
helper modules when they don't; `split_continuation` when they do).

---

## 10. Sequencing, waves, and effort

Hard ordering constraints: **Workstream A precedes every burndown**; **§9.1 (userns
repair) precedes any userns burndown (E4)**. Otherwise workstreams are independent
and parallelizable across sessions (mind `concurrent_session_build_contention` and
never `git`-write without in-conversation OP approval).

| Wave | Content | Depends on | PRs |
|---|---|---|--:|
| **A0** | Workstream A — widen 2 guards, add 2 guards, regen backlogs, wire CI + guard-tests, ratify §3 exemptions | — | 1–2 |
| **B** | `src`/`client` C: 52 → 0 (B1…B7) | A0 | 7 |
| **C** | `shared/` C: 15 shipped → 0 (+ test-`main()` disposition) | A0 (§5.2) | 3 |
| **D** | `.cpp` size: split `xrdceph_striper_migrate.cpp` | A0 (§5.1) | 1 |
| **E1** | userns **repair** (make the suite execute) | — (gates E4) | 1–2 |
| **E2** | Python CCN: 80 non-userns → 0 (E2a…E2g) | A0 (§5.3) | 7 |
| **E3** | Python size: fuzzer + probe + audit-test splits | A0 (§5.1-A) | 3 |
| **E4** | Python CCN: 73 userns → 0 + 7 part-file splits (data-driven collapse) | E1 + A0 | 4 |

Rough total: **~28–30 focused PRs.** Recommended first three, in order:
**A0 → E1 → B1**. A0 makes the whole board honest; E1 turns a fake security suite
into a real one (highest risk-retirement) and unblocks the largest offender cluster;
B1/B-series is where the shipped-code payoff starts.

**Effort signal by CCN (from §2.3–2.4 lengths):** most C offenders are 40–120 lines
with CCN 16–22 — each a 1–3 hour extraction with the suite as oracle. The Python
batteries (Pattern B) are larger (up to 290 lines) but the collapse is mechanical.
The two genuine multi-day items are E1 (userns repair — correctness, needs a
userns-capable host) and the `generators.py` 1475-line split.

---

## 11. Verification — the per-PR gate

Every burndown PR is a **pure refactor**; the strongest signal is "the suite is green
before and after, and the targeted ratchet backlog shrank."

### 11.1 Build

`make -j$(nproc)` incremental; re-`./configure --add-module=$REPO` **only** when a
new `.c`/`.cpp` TU was registered (D-split, any B/C split that adds a file) — new
`src/` files go in repo-root `./config`, new `client/` files in `client/Makefile`
(guards `check_config_coverage.py` / `check_client_build_coverage.py`). Full rebuild
when a header/struct moved (mixed-ABI gotcha — see `struct_field_abi_clean_rebuild`).
Validate `objs/nginx -t`.

### 11.2 Run the targeted ratchet — expect a *smaller* backlog

```bash
tools/ci/check_file_size.py                              # G1/G2/G6 size
tools/ci/check_complexity.py                             # src+client+shared C CCN
tools/ci/check_py_complexity.py                          # new: Python CCN
PYTHONPATH=tests python3 -m cmdscripts.lint_loc --strict # logical LoC (+ Python 600 tier)
tools/ci/check_ratchet_monotonic.py                      # proves backlogs only shrank
```

The `--regen` for the touched backlog is the PR's **last** commit, its diff showing
**only removals** (Workstream A's one widening is the sole exception, called out
explicitly).

### 11.3 Run the affected test tree (the refactor's oracle)

- `src`/`client`/`shared` C → `PYTHONPATH=tests pytest tests/<area>.py -v` + the
  in-tree `*_unittest.c` for `shared`; D-split → the ceph live/spike tests.
- Python → the module's own pytest run; for E1/E4, the userns wrapper on a
  userns-capable host (`feedback_security_modes_userns_tests`).
- Full-suite confidence per `full_suite_run_recipe` before closing each wave.

### 11.4 Reproduce any measurement in this doc

```bash
# raw file size, any tree (matches §2.2)
find src client shared -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.cc' \) \
  -exec wc -l {} + | awk '$1>600 && $2!="total"' | sort -rn
# logical LoC tiers (matches §2.2 logical column)
PYTHONPATH=tests python3 -m cmdscripts.lint_loc
# C complexity with location+length (matches §2.3)
PYTHONPATH=tools python3 -c "import readability as r; lz=r.find_lizard(); \
print(*sorted((f['ccn'],f['len'],f['file'],f['func'],f['loc']) for f in \
r.run_lizard(lz,['src','client','shared']) if f['ccn']>15, reverse=True), sep='\n')"
# Python complexity (matches §2.4) — writes the 153-row py_ccn.txt
lizard --csv -l python tests cmdscripts utils tools | python3 -c "import csv,sys; \
[print(r[1],r[4],r[6],r[7]) for r in csv.reader(sys.stdin) if len(r)>7 and r[1].isdigit() and int(r[1])>15]"
```

---

## 12. Risks, non-goals, and explicit out-of-scope

**Risks & mitigations**
- *A "pure refactor" changes behavior.* → §11 gate: full affected test tree green
  before/after; INVARIANTS 1–12 re-checked for any `src`/`shared` C change (sigver,
  CRC32c, path-confine-before-open, VFS seam, SHM discipline).
- *Regenerating a backlog masks a real regression.* → `check_ratchet_monotonic` + the
  rule that every `--regen` diff shows **only removals** outside A0; A0's one widening
  is called out and allowance-listed.
- *Splitting the userns suite before repair (the phase-38 trap, again).* → §9.1 is a
  hard prerequisite; the 73 userns rows are tagged "blocked" in the A0 backlog.
- *Lizard C++ parsing drift when `-l c` is relaxed for `.cpp`.* → pin a known-CCN C++
  fixture in `test_ci_guards` so analyzer numbers can't move under a burndown.
- *`shared/` ABI / CAS-integrity regressions.* → `shared/**/*_unittest.c` run every
  §7 PR; CAS put/reap/replay asserted byte-identical.
- *Over-eager exemption of Python test-bodies (§3.1) hides real complexity.* → the
  carve-out is `test_*::test_*` / xUnit `main()` **only**; battery *helpers*
  (`run_checks`, `base`, `srv`, `build_suites`) stay in the burndown.

**Non-goals (explicitly not this phase)**
- No features, no protocol/opcode work, no perf tuning — structure only.
- No change to the ~500 *preferred* target or the CCN-15 cap — this phase enforces
  the existing standard project-wide, it does not tighten it.
- Not touching analyzer baselines (`fanalyzer_baseline.txt`, `codechecker_baseline.txt`)
  or `duplication_backlog.txt` — those carry their own review discipline (see
  `check_ratchet_monotonic` header).

**Out of scope (not "project code" for this phase)**
- `build/`, `.rpmbuild/`, `.claude/worktrees/`, `k8s-tests/remote-suite/` shadow
  copies, `bind-exploit.bak/` — generated, vendored, or archived; never hand-maintained
  here. (These are why §11.4's `find` is rooted at `src client shared`, not `.`.)
- `shared/xrdproto/` — the vendored wire spec (already `lint_loc`-exempt; §3 extends
  the carve-out to the new guards).
- Generated `ngx_command_t[]` directive tables and other `loc-lint: exempt` files.

---

## 13. Exit criteria (phase gate)

Complete when **all** hold on a fresh clone:

1. `check_file_size.py` scans `{.c,.h,.cpp,.cc,.hpp,.hxx}` under `src`+`client`+`shared`
   (minus documented carve-outs) and its backlog is **empty**.
2. `check_complexity.py` scans `src`+`client`+`shared` C/C++ and its backlog is
   **empty** — or contains only the ratified, reason-tagged test-`main()` exemptions
   from §3.1, and nothing else.
3. `check_py_complexity.py` exists, runs in CI over `tests`+`cmdscripts`+`utils`+`tools`,
   and its backlog is **empty** (bar §3.1 pytest-body exemptions).
4. `lint_loc --strict` reports **0 SHOULD / 0 MUST**, its Python 600-tier backlog is
   **empty**, and `tools/**/*.py` is in scope.
5. `check_ratchet_monotonic.py` covers all five backlogs and is green.
6. `tests/userns/e2e_redteam*` **executes** — import-clean, 0 unresolvable names, the
   wrapper's `ALL PASSED` reached on a userns host — and its files are conformant.
7. `tests/test_ci_guards.py` asserts every guard above, so coverage cannot silently
   regress to §2.5's holes.
8. The full pytest suite is green per `full_suite_run_recipe`.

At that point "the guards are green" and "the whole tree is conformant" are the same
statement — the property this phase exists to establish.
