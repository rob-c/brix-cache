# Phase 81: Test Server Registry

## Goal

Move every test to Python/pytest and remove shell scripts from the test tree. Tests should register the nginx/xrootd topology they need before execution, then pytest session setup should render configs, start every required server, publish endpoint metadata, and own teardown.

Command-line coverage stays: Python-managed tests may still call `xrdcp`, `xrdfs`, `curl`, `brixmount`, C helpers, and other real tools. What moves out of individual tests is server lifecycle.

## Big-Bang Shell Porting Instruction

Agents working this phase should loop through every `.sh` file under `tests/`
and port it to Python in one continuous big-bang pass. Do not stop after one
script unless blocked by a reproducible technical issue or explicitly paused by
the operator. For each shell script:

1. Create an importable Python replacement under `tests/cmdscripts/` when the
   script is a command-style test, plus a `tests/test_cmd_*.py` pytest entry
   that exercises the same behavior.
2. Move nginx/xrootd lifecycle into the registry/launcher primitives whenever
   the script starts servers, and use dynamic registry/free-port allocation
   instead of fixed port literals.
3. Preserve command-line coverage by invoking real clients from Python
   (`xrdcp`, `xrdfs`, `curl`, helper binaries, etc.) through the existing command
   helpers.
4. Run the narrowest meaningful validation for the newly ported script before
   moving to the next script; mark inherited failures as `xfail` only when the
   legacy shell flow demonstrably fails the same way.
5. Update this document immediately after each script is ported: add the new
   Python files to `Completed in this pass`, annotate the corresponding shell
   checklist entry as "Python replacement exists; shell deletion remains", and
   update migrated command counts or xfail notes.

The loop is complete only when no `.sh` file remains under `tests/`, including
wrappers and helper scripts. Until then, this tracker is the source of truth for
which scripts are ported, which shells are pending deletion, and which failures
are inherited rather than introduced by the Python migration.

## Implementation Status — 2026-07-16

**Deletion sweep executed 2026-07-16 (OP-approved):** all 193 ported `.sh`
files under `tests/` were deleted. Only the compatibility fleet backend
survives: `tests/manage_test_servers.sh` + the 8 `tests/lib/*.sh` helpers it
sources. Live consumers were repointed first: `.github/workflows/loc.yml` →
`python3 -m cmdscripts.lint_loc --strict`; `tools/git-hooks/pre-push` →
`python3 -m cmdscripts.operator_runtime suite --fast`;
`tests/test_server_registry_lint.py` now enforces zero stray shells outside
the keep-list. Post-deletion sweep of all port collectors + migrated suites:
136 passed, 89 skipped (opt-in/env), 6 xfailed (documented inherited), 0
failed. Port bugs fixed during verification: xmeta compile line updated for
the xmeta_encode/decode file split; cache-af-family pidfile-name mismatch
(leaked nginx on 11940/11941) + binary-vs-text capture; xfer-audit-sink and
proxy-metadata-phase lazy check evaluation reading state after later
lifecycle steps destroyed it; default 120s timeout added to `cmdscripts.run()`
so a wedged client can no longer hang the whole pytest process;
`x509_oracle` xfailed (same link failure as the deleted shell).

Big-bang porting pass completed 2026-07-16: every remaining "Pending direct
Python port" script (~66 shell entry points) now has a direct Python port under
`tests/cmdscripts/` with a `tests/test_cmd_*` (or `test_cvmfs_*`/`test_ceph_*`)
collector. New live modules: `tpc_fwd_live`, `fwd_matrix_live`, `gsi_trust_live`,
`tap_proxy_live`, `user_backend_cred`, `cred_metrics`, `cvmfs_live_ext`,
`brixcvmfs_live`, `cvmfs_matrix`, `tier_stage_live`, `tape_live`, `pblock_live`,
`cachestore_live`, `official_interop`, `client_features`, `dashboard_demo_live`,
`ceph_harness`. All live scenarios are opt-in via `@pytest.mark.optin` +
`PHASE81_RUN_LIVE_PORTS=1` (Ceph lifecycle: `PHASE81_RUN_CEPH_PORTS=1`); the
`optin` marker is registered in `pytest.ini`. Inherited failures (verified
identical under the legacy shells, not port bugs) are annotated per-entry in the
deletion ledger below: fwd-brix-brix C-HH-token cell, cvmfs evict propagation,
the tape-recall double-free server crash, and the cachestore-sidecar cinfo
I/O error.

Python callers that executed shell runners were migrated the same day, so no
pytest file invokes a `.sh` anymore: `test_cache_lock_reclaim` /
`test_shm_mutex_recovery` / `test_ratelimit_gauge_reset` now call
`cmdscripts.c_regression_units`; `test_slice_cache` calls
`cmdscripts.c_object_units` (slice + cinfo); `test_phase27_memsafety` calls
`cmdscripts.lint_alloc`; `test_compression_build_matrix` calls
`cmdscripts.operator_build.build_dynamic_modules`; `test_valgrind_regression`
runs `python3 -m cmdscripts.operator_runtime valgrind`
(`operator_runtime.run_valgrind` was extended to full parity with
`tests/valgrind/run_valgrind.sh` — request mix, worker-first graceful shutdown,
master-log discard, MODULE-FRAME triage, `DONE` marker — and passes the opt-in
`RUN_VALGRIND=1` Memcheck test end to end); `test_phase0_guardrails` /
`test_phase1_commodity_libraries` assert markers in
`tests/cmdscripts/unit_tests.py`; and the six FRM/evil-actor fixtures copy
`tests/cmdscripts/frm_fake_mss.py` (now executable with a shebang) as the recall
payload instead of `frm_fake_mss.sh`.

Remaining shell: deletion sweep only (needs OP approval; `tests/lib/*.sh` and
`tests/manage_test_servers.sh` stay — they are the compatibility fleet backend).

### Status — 2026-07-15

Phase 81 is now partially implemented as a registry-backed pytest lifecycle
foundation. Pytest routes local lifecycle through `tests/server_registry.py` and
`tests/server_launcher.py`; the current fixed-port fleet is registered as a
compatibility server so the existing shell fleet remains usable while individual
tests migrate to first-class registry specs.

Completed in this pass:

- Added the registry model, manifest serialization, dependency ordering, stable
  dynamic port reservation, endpoint lookup, and compatibility-fleet registration.
- Added command-suite specs, xrootd/server/manifest compatibility aliases,
  duplicate registration diagnostics with source locations, and selected-spec
  dependency closure wired through pytest collection/startup.
- Added the launcher with template rendering, strict placeholder support,
  `nginx -t`, start/stop/reload/reopen/restart helpers, worker kill/snapshot,
  config-failure checks, privileged-step skip handling, command runner, readiness
  aliases, and structured nginx failure reports.
- Wired pytest session startup/teardown through the registry launcher, with
  xdist workers reading `$TEST_ROOT/registry/manifest.json` instead of starting
  servers.
- Added pytest-facing `registry`, `registry_server`, and `command_runner`
  fixtures for migrated tests.
- Added importable command-script helpers for future Python replacements of
  former shell entry points.
- Ported `tests/run_af_family_conf.sh` into
  `tests/cmdscripts/af_family_conf.py` plus `tests/test_cmd_af_family_conf.py`
  as the first Python-managed command proof.
- Ported `tests/run_cache_pblock_pblock.sh` into
  `tests/cmdscripts/cache_pblock_pblock.py` plus
  `tests/test_cmd_cache_pblock_pblock.py`.
- Ported `tests/run_credential_http_bearer.sh` into
  `tests/cmdscripts/credential_http_bearer.py` plus
  `tests/test_cmd_credential_http_bearer.py`; the pytest is xfailed because the
  original shell flow currently fails the same authenticated-fill checks.
- Ported `tests/run_credential_webdav_xroot.sh` into
  `tests/cmdscripts/credential_webdav_xroot.py` plus
  `tests/test_cmd_credential_webdav_xroot.py`.
- Ported `tests/run_storage_backend_metrics.sh` into
  `tests/cmdscripts/storage_backend_metrics.py` plus
  `tests/test_cmd_storage_backend_metrics.py`.
- Ported `tests/run_dashboard_vfs_browse.sh` into
  `tests/cmdscripts/dashboard_vfs_browse.py` plus
  `tests/test_cmd_dashboard_vfs_browse.py`.
- Ported `tests/run_storage_backend_schemes.sh` into
  `tests/cmdscripts/storage_backend_schemes.py` plus
  `tests/test_cmd_storage_backend_schemes.py`; the pytest is xfailed for the
  FRM recall data-plane check because the original shell flow currently fails
  the same check.
- Ported `tests/run_s3_usermeta.sh` into `tests/cmdscripts/s3_usermeta.py`
  plus `tests/test_cmd_s3_usermeta.py`.
- Ported `tests/run_s3_store_writable.sh` into
  `tests/cmdscripts/s3_store_writable.py` plus
  `tests/test_cmd_s3_store_writable.py`.
- Ported `tests/run_s3_storage_backend.sh` into
  `tests/cmdscripts/s3_storage_backend.py` plus
  `tests/test_cmd_s3_storage_backend.py`.
- Ported `tests/run_cache_http_source.sh` into
  `tests/cmdscripts/cache_http_source.py` plus
  `tests/test_cmd_cache_http_source.py`.
- Ported `tests/run_cache_xroot_origin.sh` into
  `tests/cmdscripts/cache_xroot_origin.py` plus
  `tests/test_cmd_cache_xroot_origin.py`.
- Ported `tests/run_cache_s3_origin.sh` into
  `tests/cmdscripts/cache_s3_origin.py` plus
  `tests/test_cmd_cache_s3_origin.py`; the pytest is xfailed because the
  original shell flow currently fails the same SigV4 cache-fill checks.
- Ported `tests/run_cache_backend_source.sh` into
  `tests/cmdscripts/cache_backend_source.py` plus
  `tests/test_cmd_cache_backend_source.py`.
- Ported `tests/run_cache_pblock_posix.sh` into
  `tests/cmdscripts/cache_pblock_posix.py` plus
  `tests/test_cmd_cache_pblock_posix.py`.
- Ported `tests/run_cache_wt_driver.sh` into
  `tests/cmdscripts/cache_wt_driver.py` plus
  `tests/test_cmd_cache_wt_driver.py`.
- Ported `tests/run_cache_watermark.sh` into
  `tests/cmdscripts/cache_watermark.py` plus
  `tests/test_cmd_cache_watermark.py`; the Python helper links the current
  xmeta/CRC32c objects explicitly.
- Ported `tests/run_cache_watermark_config.sh` into
  `tests/cmdscripts/cache_watermark_config.py` plus
  `tests/test_cmd_cache_watermark_config.py`.
- Ported `tests/run_cache_reaper.sh` into
  `tests/cmdscripts/cache_reaper.py` plus
  `tests/test_cmd_cache_reaper.py`; the Python helper links the current
  xmeta/CRC32c objects explicitly.
- Ported `tests/run_cache_stage_throttle.sh` into
  `tests/cmdscripts/cache_stage_throttle.py` plus
  `tests/test_cmd_cache_stage_throttle.py`.
- Ported `tests/run_cache_slice_gsi_legacy.sh` into
  `tests/cmdscripts/cache_slice_gsi_legacy.py` plus
  `tests/test_cmd_cache_slice_gsi_legacy.py`.
- Ported `tests/run_cache_unit.sh` into `tests/cmdscripts/cache_unit.py`
  plus `tests/test_cmd_cache_unit.py`.
- Ported `tests/run_credential_xroot_ztn.sh` into
  `tests/cmdscripts/credential_xroot_ztn.py` plus
  `tests/test_cmd_credential_xroot_ztn.py`; the pytest is xfailed because the
  original shell flow currently fails the same token root credential fill checks.
- Ported `tests/run_credential_xroot_gsi_writeback.sh` into
  `tests/cmdscripts/credential_xroot_gsi_writeback.py` plus
  `tests/test_cmd_credential_xroot_gsi_writeback.py`.
- Ported `tests/run_credential_xroot_gsi.sh` into
  `tests/cmdscripts/credential_xroot_gsi.py` plus
  `tests/test_cmd_credential_xroot_gsi.py`; the Python helper now uses dynamic
  `free_ports(5)` instead of the legacy fixed `11704`-`11708` block.
- Ported `tests/run_credential_wt_ztn.sh` into
  `tests/cmdscripts/credential_wt_ztn.py` plus
  `tests/test_cmd_credential_wt_ztn.py`.
- Ported `tests/run_credential_dup_warn.sh` into
  `tests/cmdscripts/credential_dup_warn.py` plus
  `tests/test_cmd_credential_dup_warn.py`.
- Ported `tests/run_delegation_twostep.sh` into
  `tests/cmdscripts/delegation_twostep.py` plus
  `tests/test_cmd_delegation_twostep.py`.
- Ported `tests/run_cvmfs_catalog_unit.sh` into
  `tests/cmdscripts/cvmfs_catalog_unit.py` plus
  `tests/test_cvmfs_catalog_unit.py`.
- Ported `tests/run_cvmfs_classify.sh` into
  `tests/cmdscripts/cvmfs_classify.py` plus
  `tests/test_cvmfs_classify.py`.
- Ported `tests/run_overlay_unit.sh` into
  `tests/cmdscripts/overlay_unit.py` plus
  `tests/test_cmd_overlay_unit.py`.
- Ported `tests/run_proxy_env_unit.sh` into
  `tests/cmdscripts/proxy_env_unit.py` plus
  `tests/test_cmd_proxy_env_unit.py`.
- Ported `tests/run_ucred_conf.sh` into
  `tests/cmdscripts/ucred_conf.py` plus `tests/test_cmd_ucred_conf.py`.
- Ported `tests/lint_alloc.sh` into `tests/cmdscripts/lint_alloc.py` plus
  `tests/test_cmd_lint_alloc.py`.
- Ported `tests/lint_loc.sh` into `tests/cmdscripts/lint_loc.py` plus
  `tests/test_cmd_lint_loc.py`.
- Ported `tests/run_brixmount_unit.sh` into
  `tests/cmdscripts/brixmount_unit.py` plus
  `tests/test_cmd_brixmount_unit.py`.
- Ported `tests/guard/run_guard_core.sh` into
  `tests/cmdscripts/guard_core.py` plus `tests/test_cmd_guard_core.py`.
- Ported `tests/c/run_vo_token_tests.sh` into
  `tests/cmdscripts/c_vo_token.py` plus `tests/test_c_vo_token.py`.
- Ported `tests/c/run_signing_policy_tests.sh` into
  `tests/cmdscripts/c_signing_policy.py` plus
  `tests/test_c_signing_policy.py`.
- Ported `tests/run_cvmfs_conf_unit.sh` into
  `tests/cmdscripts/cvmfs_conf_unit.py` plus
  `tests/test_cvmfs_conf_unit.py`.
- Ported `tests/run_cvmfs_fetch_unit.sh` into
  `tests/cmdscripts/cvmfs_fetch_unit.py` plus
  `tests/test_cvmfs_fetch_unit.py`.
- Ported small standalone C unit shell runners into
  `tests/cmdscripts/c_simple_units.py` plus `tests/test_c_simple_units.py`,
  covering `tests/c/run_fs_usage_tests.sh`,
  `tests/c/run_meta_advisory_tests.sh`, `tests/c/run_site_n2n_tests.sh`,
  `tests/c/run_stage_admit_tests.sh`, `tests/c/run_sd_ceph_compat_tests.sh`,
  and `tests/c/run_sesslog_tests.sh`; the `sesslog` pytest is xfailed because
  the legacy shell runner fails against the current sesslog API.
- Ported `tests/run_token_conformance.sh` into
  `tests/cmdscripts/token_conformance.py` plus
  `tests/test_cmd_token_conformance.py`.
- Ported `tests/run_x509_differential.sh` into
  `tests/cmdscripts/x509_differential.py` plus
  `tests/test_cmd_x509_differential.py`.
- Ported `tests/run_x509_matrix_differential.sh` into
  `tests/cmdscripts/x509_matrix_differential.py` plus
  `tests/test_cmd_x509_matrix_differential.py`.
- Ported `tests/c/test_xrdcinfo.sh` into `tests/cmdscripts/c_xrdcinfo.py`
  plus `tests/test_c_xrdcinfo.py`; the pytest is xfailed because the legacy
  shell runner currently fails the same cinfo magic checks.
- Ported object-linked C shell runners into
  `tests/cmdscripts/c_object_units.py` plus `tests/test_c_object_units.py`,
  covering `tests/c/run_cache_admit_tests.sh`,
  `tests/c/run_cache_storage_tests.sh`, `tests/c/run_cinfo_tests.sh`,
  `tests/c/run_slice_tests.sh`, and `tests/c/run_vfs_caps_tests.sh`.
- Ported `tests/run_token_differential.sh` into
  `tests/cmdscripts/token_differential.py` plus
  `tests/test_cmd_token_differential.py`.
- Ported `tests/unit/run_tests.sh` into `tests/cmdscripts/unit_tests.py`
  plus `tests/test_cmd_unit_tests.py`; the pytest is xfailed because the legacy
  shell runner currently fails the same `test_xml_compat.c` link check.
- Ported `tests/fuzz/run_all.sh` into `tests/cmdscripts/fuzz_all.py` plus
  `tests/test_cmd_fuzz_all.py`; the pytest is opt-in because it builds and runs
  libFuzzer targets.
- Ported auth-oriented C shell runners into `tests/cmdscripts/c_auth_units.py`
  plus `tests/test_c_auth_units.py`, covering
  `tests/c/run_x509_conformance_tests.sh`, `tests/c/run_x509_oracle.sh`,
  `tests/c/run_cred_mint.sh`, and `tests/c/run_ucred_tests.sh`; the
  `x509_conformance` pytest is xfailed because the legacy shell runner fails
  the same current link step.
- Ported heavy operator/build shell entrypoints into
  `tests/cmdscripts/operator_build.py` plus `tests/test_cmd_operator_build.py`,
  covering `tests/brutal_teardown.sh`, `tests/build_dynamic_modules.sh`, and
  `tests/build_sanitizer.sh`; the pytest is opt-in because these actions are
  destructive or rebuild the tree.
- Ported CVMFS driver/build shell runners into
  `tests/cmdscripts/cvmfs_driver_units.py` plus
  `tests/test_cvmfs_driver_units.py`, covering
  `tests/run_cvmfs_core_unit.sh`, `tests/run_cvmfs_client_unit.sh`,
  `tests/run_brixcvmfs_build.sh`, and `tests/run_brixcvmfs_check.sh`; the live
  `--check` path starts `python3 -m http.server` through `subprocess.Popen` and
  reports a sandbox skip when local sockets are unavailable.
- Ported object-linked and standalone C regression shell runners into
  `tests/cmdscripts/c_regression_units.py` plus
  `tests/test_c_regression_units.py`, covering
  `tests/c/run_cache_lock_reclaim_tests.sh`,
  `tests/c/run_flush_deadletter.sh`,
  `tests/c/run_shm_mutex_recovery_tests.sh`,
  `tests/c/run_ratelimit_gauge_reset_tests.sh`,
  `tests/c/run_delegation_store.sh`, `tests/c/run_pblock_tests.sh`,
  `tests/c/run_mu_unit.sh`, `tests/c/run_stage_reconcile_tests.sh`,
  `tests/c/run_compression_tests.sh`, `tests/c/run_sreq_compat.sh`, and
  `tests/c/run_sd_remote_wrongkind_tests.sh`; the Python port links the current
  split objects/source files explicitly.
- Ported top-level operator runtime shell entrypoints into
  `tests/cmdscripts/operator_runtime.py` plus
  `tests/test_cmd_operator_runtime.py`, covering `tests/run_suite.sh`,
  `tests/run_load_test.sh`, `tests/profile_lifecycle.sh`,
  `tests/profile_load.sh`, and `tests/valgrind/run_valgrind.sh`; execution is
  opt-in because these lanes run pytest fleets, perf, valgrind, or mutate
  `/tmp` process state.
- Ported the shared shell helper libraries into `tests/lib_py/` plus
  `tests/test_lib_py_shell_ports.py`, covering `tests/lib/util.sh`,
  `tests/lib/pki.sh`, `tests/lib/nginx.sh`, `tests/lib/refxrootd.sh`,
  `tests/lib/xrdhttp.sh`, `tests/lib/dedicated.sh`,
  `tests/lib/fwd_matrix.sh`, and `tests/lib/tpc_fwd.sh`; the Python layer
  exposes importable lifecycle/config/PKI/forwarding helpers for remaining
  driver ports.
- Ported Ceph container/live shell harnesses into
  `tests/cmdscripts/ceph_operator.py` plus `tests/test_cmd_ceph_operator.py`,
  covering `tests/ceph/build_in_container.sh`,
  `tests/ceph/run_striper_migrate.sh`, `tests/ceph/run_rescue_tools.sh`,
  `tests/ceph/run_cephfs_ro_live.sh`, `tests/ceph/ceph_export_smoke.sh`,
  `tests/ceph/run_py_migrate.sh`, `tests/ceph/run_sd_ceph_cred_live.sh`,
  `tests/ceph/cephfs_ro_smoke.sh`, and `tests/ceph/run_sd_ceph_live.sh`;
  execution is opt-in because it requires Docker and a live Ceph harness.
- Ported the fleet manager, user namespace runner, and FRM fake-MSS helper into
  `tests/cmdscripts/manage_test_servers.py`,
  `tests/cmdscripts/userns_run.py`, and
  `tests/cmdscripts/frm_fake_mss.py`.
- Rejected the former `live_scenarios.py` pytest-dispatch approach because it
  did not port the shell implementations. Direct command ports now use
  `tests/cmdscripts/live_common.py` for Python-owned process, nginx, curl,
  temporary-directory, and cleanup mechanics.
- Directly ported `tests/run_cvmfs_verify.sh`,
  `tests/run_tier_matrix_drivers.sh`, and `tests/run_http_store_writable.sh`
  into `tests/cmdscripts/cvmfs_verify.py`,
  `tests/cmdscripts/tier_matrix_drivers.py`, and
  `tests/cmdscripts/http_store_writable.py`. Each module renders its nginx
  configuration, starts its mock/server processes with `subprocess.Popen`, and
  makes the corresponding HTTP assertions without executing a shell script.
- Directly ported `tests/run_tier_remote_stage.sh`,
  `tests/run_tier_remote_evict.sh`, `tests/run_tier_remote_store.sh`,
  `tests/run_tier_sidecar_meta.sh`, and `tests/run_tier_slice_fill.sh` into
  `tests/cmdscripts/tier_remote.py`. The module has separate Python scenario
  functions for each source script's remote topology and acceptance sequence.
- Directly ported `tests/run_cvmfs_minimal.sh`,
  `tests/run_cvmfs_manifest.sh`, `tests/run_cvmfs_conn_reuse.sh`,
  `tests/run_cvmfs_failover.sh`, `tests/run_cvmfs_shared_cache.sh`, and
  `tests/run_cvmfs_keepalive.sh` into `tests/cmdscripts/cvmfs_live.py`.
  These are Python-owned mock-origin/server/client flows, including the
  original cache, failover, and socket durability assertions.
- Directly ported `tests/run_remote_backend_serve_offload.sh`,
  `tests/run_remote_backend_write.sh`, `tests/run_remote_backend_staging.sh`,
  `tests/run_remote_backend_webdav.sh`, and `tests/run_stage_reconcile.sh`
  into `tests/cmdscripts/remote_backend.py`, with dedicated functions for the
  source scripts' remote-root, staging, and recovery flows.
- Directly ported `tests/run_unified_conf.sh` into
  `tests/cmdscripts/unified_conf.py` plus `tests/test_cmd_unified_conf.py`.
  The Python port renders each nginx config body and runs `nginx -t` directly.
- Directly ported `tests/run_cache_af_family.sh`,
  `tests/run_io_uring_backend.sh`, `tests/run_ktls.sh`, and
  `tests/run_proxy_metadata_phase.sh` into
  `tests/cmdscripts/system_live_ports.py` plus
  `tests/test_cmd_system_live_ports.py`. These functions own their temporary
  nginx topologies and command-line client probes in Python; live execution is
  opt-in because the scenarios depend on local nginx/client/kernel features.
- Directly ported `tests/run_xmeta.sh`, `tests/run_nonstaged_reap.sh`,
  `tests/run_sd_s3_meta.sh`, and `tests/run_xfer_audit_sink.sh` into
  `tests/cmdscripts/metadata_live_ports.py` plus
  `tests/test_cmd_metadata_live_ports.py`. These ports compile/run the C helper
  or own the nginx/client live probe directly from Python.
- Added registry smoke/lint tests and registry migration documentation.
- Documented registry migration recipes, command-script naming, zero-shell
  policy, registry manifest/log paths, and phase env knobs.
- Kept attach mode, remote mode, and `TEST_SKIP_SERVER_SETUP=1` safe.
- Fixed several full-suite isolation issues discovered while validating the
  transition (`nginx_stream_guard.conf` comment substitution, IPv6 HTTP
  connection host handling, deterministic zip/GSI/interop fixture seeding).

Deferred:

- The full shell removal is not complete. Rows marked "Pending direct Python
  port" have no valid replacement yet and must not be represented by a generic
  dispatcher or a shell wrapper.
- The existing fixed-port shell fleet is still the compatibility backend behind
  the Python registry. `tests/lib_py/*` replacements are not complete.
- Many Python tests still contain direct self-start lifecycle fixtures and remain
  migration targets.
- Fast-suite validation improved substantially but is not yet fully green in this
  workspace. The last clean-focused checks passed, while the most recent fresh
  fast run still showed stateful failures in `tests/test_manager_mode.py`,
  `tests/test_zip_member.py`, and `tests/userns/test_creds_guard.py`.
- Latest migrated command/registry lane before this batch:
  `36 passed, 4 xfailed` for the then-ported command scripts plus registry
  smoke/lint tests; the xfails reproduce failures in the corresponding legacy
  shell flows. This batch additionally validated the CVMFS core/client/build
  ports, pblock/idmap/compression ports, and the object-linked C regression
  ports directly.

## Done Means

- [x] Test configs stay reviewable under `tests/configs/`.
- [ ] Python tests do not hand-roll nginx start/stop outside the registry/lifecycle harness.
- [ ] Shell tests are migrated to Python/pytest.
- [ ] No `.sh` file remains in `tests/`, including wrappers.
- [x] Registered servers start before the first test body executes.
- [x] xdist workers consume a shared `$TEST_ROOT/registry/manifest.json`.
- [x] Attach mode, remote mode, and `TEST_SKIP_SERVER_SETUP=1` remain safe.
- [x] Command-line tests still execute real command-line clients from Python.
- [ ] Former operator entry points are Python modules or pytest targets, not shell wrappers.

## New Files

- [x] `tests/server_registry.py` - registration API, spec model, manifest read/write.
- [x] `tests/server_launcher.py` - render, `nginx -t`, start, readiness, stop.
- [x] `tests/cmdscripts/__init__.py` - package for Python replacements of former `run_*.sh` scripts.
- [x] `tests/test_server_registry_smoke.py` - minimal registry-backed smoke test.
- [x] `tests/test_server_registry_lint.py` - documents the unregistered lifecycle backlog during migration.
  - [ ] Fails if any `.sh` file exists under `tests/` after the migration is complete.
- [x] `tests/configs/nginx_registry_smoke.conf` - tiny starter template if no existing template fits cleanly.
- [x] `tests/configs/REGISTRY_MIGRATION.md` - operator notes and mandatory migration policy.

## Existing Harness Files To Edit

- [x] `tests/conftest.py`
  - [x] Register marker `uses_lifecycle_harness`.
  - [x] Register `registry_server` and `registry_servers` markers.
  - [x] Start registry servers after shared data/PKI setup.
  - [x] Skip registry startup in remote/attach/skip modes.
  - [x] In xdist controller, write manifest.
  - [x] In xdist workers, read manifest and never start servers.
  - [x] Stop registry-owned servers during session teardown.

- [x] `tests/settings.py`
  - [x] Add registry paths: `REGISTRY_ROOT`, `REGISTRY_MANIFEST`.
  - [x] Add env overrides for registry behavior.
  - [x] Add helpers for stable per-session port allocation.

- [x] `tests/config_templates.py`
  - [x] Keep existing literal template rendering.
  - [x] Add unresolved-placeholder detection.
  - [x] Add optional strict mode for registry launches.

- [ ] `tests/manage_test_servers.sh` - Python replacement exists in `tests/cmdscripts/manage_test_servers.py`; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
  - [ ] Replace authoritative test lifecycle behavior with Python registry calls.
  - [ ] Replace the shell entry point with Python command/module documentation.
  - [ ] Remove direct nginx/xrootd start logic from the test runner path.

- [ ] `tests/lib/dedicated.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
  - [ ] Port behavior to `tests/lib_py/dedicated.py`.
  - [ ] Remove from authoritative test execution.

- [ ] `tests/lib/nginx.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
  - [ ] Port behavior to `tests/lib_py/nginx.py`.
  - [ ] Remove shell start/stop behavior from authoritative test execution.

- [ ] `tests/lib/util.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
  - [ ] Port needed helpers to Python.
  - [ ] Remove shell config rendering from authoritative test execution.

- [x] `TESTING.md`
  - [x] Document registry mode, attach mode, and migration policy.

- [x] `README.md`
  - [x] Add short note pointing developers to registry docs for new tests.

## Registry API Checklist

- [x] Define `NginxInstanceSpec`.
- [x] Fields:
  - [x] `name`
  - [x] `template`
  - [x] `port`
  - [x] `protocol`
  - [x] `data_root`
  - [x] `extra_ports`
  - [x] `env`
  - [x] `template_values`
  - [x] `readiness`
  - [x] `requires`
  - [x] `tags`
  - [x] `allow_remote_skip`
  - [x] `reason`
- [x] Implement `register_nginx(spec)`.
- [x] Implement `register_xrootd(spec)` compatibility alias.
- [x] Implement `CommandSpec` and `register_command_suite(spec)`.
- [x] Implement `get_server(name)`.
- [x] Implement `server(name)` compatibility alias.
- [x] Implement dependency ordering.
- [x] Implement duplicate-name detection with file/line diagnostics.
- [x] Implement free-port reservation before render.
- [x] Implement endpoint interpolation between specs.
- [x] Implement manifest serialization.
- [x] Implement `manifest_write` and `manifest_read` aliases.
- [x] Implement manifest validation for workers.
- [x] Implement `selected_specs(pytest_items)` dependency closure.
- [x] Wire `selected_specs(pytest_items)` into session startup/teardown.
- [x] Implement readable startup failure reports.
- [x] Implement pidfile cleanup.
- [x] Implement process-group cleanup.
- [x] Implement final leak check for registry-owned nginx processes.

## Special Lifecycle Coverage

No test is exempt from Python/pytest ownership. Tests whose subject is lifecycle behavior must use Python harness primitives rather than unmanaged shell or ad hoc per-test server launch code.

Required lifecycle harness primitives:

- [x] `registry.start(spec)` for controlled startup.
- [x] `registry.stop(name)` for controlled shutdown.
- [x] `registry.reload(name)` for `nginx -s reload` coverage.
- [x] `registry.reopen(name)` for `nginx -s reopen` coverage.
- [x] `registry.expect_config_failure(spec)` for invalid config tests.
- [x] `registry.kill_worker(name, signal)` for worker crash/fork-safety tests.
- [x] `registry.restart(name)` for restart durability tests.
- [x] `registry.process_snapshot(name)` for master/worker accounting tests.
- [x] `registry.run_privileged_step(...)` for userns/mount/privileged setup, skipped cleanly when unavailable.
- [x] `registry.run_cmd(...)` wrapper around `subprocess.run` for command-line clients.

Files requiring lifecycle-harness migration:

- [x] `tests/test_reload.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_lifecycle_reload.conf` + `nginx_lifecycle_broken.conf`); 6/6 pass.
- [x] `tests/test_lifecycle_speed.py` - migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lifecycle_speed.conf`); 4/4 pass.
- [x] `tests/test_shm_fork_safety.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_shm_fork_comprehensive.conf` + `nginx_shm_fork_minimal.conf`); comprehensive tier restored (old inline config had silently degraded to minimal since the 2026-06-30 `brix_frm*` removal); 2/2 pass.
- [x] `tests/test_phase22_health_check.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_hc_parse.conf` + `nginx_hc_toggle.conf` + `nginx_hc_cluster.conf`); 9/9 pass.
- [x] `tests/test_phase21_proxy_filter.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_xrdhttp_filter.conf` + `nginx_webdav_introspect.conf`); retired `brix_webdav_proxy`/`_upstream` tests reduced to documented skip stubs; 11 pass, 3 skip.
- [x] `tests/test_phase23_admin_api.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_admin_parse.conf` + `nginx_admin_badsecret.conf` + `nginx_admin_api.conf`); proxy-pool lifecycle skip-stubbed (pool SHM zone unreachable since `brix_webdav_proxy_dynamic` retirement); 12 pass, 2 skip.
- [x] `tests/test_phase24_mirror.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_mirror_http.conf` + `nginx_mirror_stream_parse.conf` + `nginx_mirror_stream_pair.conf`); 21/21 pass.
- [x] `tests/test_phase25_ratelimit.py` - migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_rl_http.conf` + `nginx_rl_stream.conf`); curl via `run_cmd`; 23/23 pass.
- [~] `tests/userns/e2e_redteam.py` - DEFERRED (documented lint allowlist entry, not a raw-launch backlog item). This is a standalone in-namespace-root script (launched by the C `userns_exec_launcher`, not a shell — the "no shell launcher" criterion is already met) that boots the real nginx with `user svc;` + `brix_impersonation map` and drives a security-critical privilege-escalation battery. Its per-uid/gid export-tree ownership, `user svc` worker-setuid model, and AF_UNIX socket-path (<108 char) requirements conflict with the registry's prefix-ownership model, and the battery is currently red in the dev sandbox (37 downstream S3/native-client failures + >560s runtime, unrelated to how nginx is launched), so a registry-boot rewrite cannot be verified green here. Tracked instead via an explicit, rationale-carrying entry in `test_server_registry_lint.py`'s allowlist (2026-07-16); revisit once the S3/native-client baseline is green in CI.
- [x] `tests/userns/run.sh` - Python replacement exists in `tests/cmdscripts/userns_run.py`; shell deleted 2026-07-16.
- [x] `tests/valgrind/run_valgrind.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/build_dynamic_modules.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/build_sanitizer.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/brutal_teardown.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_suite.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [ ] `tests/manage_test_servers.sh` - Python replacement exists in `tests/cmdscripts/manage_test_servers.py`; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).

## Python Migration Targets

### Single-Server, Low Risk

- [x] `tests/test_client_xrd_frontend.py` — migrated 2026-07-16 to `LifecycleHarness` (new shared template `nginx_lc_stream_posix_anon.conf` — writable anon root:// server for the client-tool suites; module-scoped `_client_built` keeps the `make` once, function-scoped `rw` starts the server with a `tmp_path`-seeded data dir); 8/8 pass.
- [x] `tests/test_client_xrd_doctor_login.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrd-doctor-login`; module-scoped `_client_built` builds `xrd` once, function-scoped `server` starts a `tmp_path`-seeded anon root); 4/4 pass.
- [x] `tests/test_xrd_busybox.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrd-busybox`; function-scoped `rw`); 56/56 pass.
- [x] `tests/test_client_xrdrc_alias.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrdrc-alias`; function-scoped `rc_env` writes the `xrdrc` alias against `ep.port`); 6/6 pass.
- [x] `tests/test_xrddiag_capture.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrddiag-capture`; function-scoped `anon` yields `(ep.port, tmp_path)`); 4/4 pass.
- [x] `tests/test_xrddiag_watch.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrddiag-watch`; function-scoped `server` returns `{"rport": ep.port}`); 4/4 pass.
- [x] `tests/test_xrddiag_probe.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrddiag-probe`; function-scoped `anon_server`); 5/5 pass.
- [x] `tests/test_client_xrdfs_tools.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrdfs-tools`; function-scoped `tree_root`); 7/7 pass.
- [x] `tests/test_client_xrdcp_bulk.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrdcp-bulk`; function-scoped `rw`); 16/16 pass.
- [x] `tests/test_xrdmapc.py` — migrated 2026-07-16 to `LifecycleHarness` (shared `nginx_lc_stream_posix_anon.conf`; spec `lc-xrdmapc`; function-scoped `anon`; the two cluster-redirector tests still target the separate fleet port); 7/7 pass.
- [x] `tests/test_native_client_diagnostics.py` — migrated 2026-07-16 to `LifecycleHarness` (only the self-hosted `anon_self` fixture migrated → spec `lc-native-client-diag` on shared `nginx_lc_stream_posix_anon.conf`; the wire-trace/timing/explain tests still target the shared anon + GSI-TLS fleet ports, which launch no nginx directly); 11/11 pass.
- [x] `tests/test_client_web_transfer.py` — migrated 2026-07-16 to `LifecycleHarness` (new 2-server template `nginx_lc_client_web_transfer.conf` — one nginx hosting WebDAV on `{PORT}` + S3 on `extra_ports={"S3_PORT"}`; spec `lc-client-web-transfer`, protocol `http`); 15 pass, 3 skip (pre-existing `vfs_s3_smoke` build gap, unrelated).
- [x] `tests/test_dashboard_config_anon.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_dashboard_config_anon.conf`; stream root:// origin via `extra_ports={"ROOT_PORT"}`; planted secrets passed as `template_values`); 16/16 pass.
- [x] `tests/test_dashboard_files.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_dashboard_files.conf`; second no-browse-root server via `extra_ports={"OFF_PORT"}`; browse root = `{DATA_ROOT}`, traversal-target secret seeded in its parent); 10/10 pass.
- [x] `tests/test_storage_backend_panel.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_storage_backend_panel.conf`; dead-origin xroot export namespace pre-created under `TEST_ROOT` and passed as `REMOTE_NS`); 4/4 pass.
- [x] `tests/test_scan.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_scan_dashboard.conf`; `brix_scan_root` is parse-time validated so the seeded tree is pre-created under `tmp_path` and passed as absolute `DATA_DIR`; scan-disabled second server via `extra_ports={"OFF_PORT"}`); 15/15 pass.
- [x] `tests/test_arc_guard.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_guard_arc_lc.conf`; module-scoped `StubBackend` retained, `GuardServer.wait_ready("/arex/ready")` readiness); 7/7 pass.
- [x] `tests/test_guard_endpoints.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_guard_endpoints_lc.conf`; five front doors via `extra_ports={DAV,S3,OPS,XRD,CMS}_PORT`, `readiness="none"` + manual `_port_alive` wait; export roots/audits under `tmp_path`). `test_emitted_lines_match_filters` reworked to emit its own signature/notfound/authfail lines (was relying on module-scoped audit accumulation); 20/20 pass.
- [x] `tests/test_xrdhttp_guard.py` — 4/4 green (2026-07-16); guard proxy via harness, StubBackend/GuardServer helpers retained.
- [x] `tests/test_stream_guard.py` — migrated 2026-07-16 to `LifecycleHarness` (three stream specs: origin `nginx_lc_stream_guard_origin.conf` + guarded/unguarded relays `nginx_lc_stream_guard_relay.conf` chained via `ORIGIN_PORT`; guard audit lines read from each relay's `{LOG_DIR}/error.log`; export seeded under `tmp_path` for parse-time validation); 4/4 pass.
- [x] `tests/test_netfault_stream.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_netfault_stream.conf`; `daemon off/master_process off` Popen replaced by the daemonized harness, dynamic port returned via the `nf_server` tuple; per-connection deadline values threaded as `template_values`, data dir seeded under `tmp_path`); 5/5 pass.
- [x] `tests/test_phase27_memsafety.py` — migrated 2026-07-16 to `LifecycleHarness` (functional readv tests only; template `nginx_lc_memsafety_stream.conf`; `daemon off/master_process off` Popen on fixed ports 21870/21871 replaced by daemonized harness with dynamic ports, data dir seeded under `tmp_path`; source-marker/fuzz/lint tests untouched); 12/12 pass.
- [x] `tests/test_cache_reap_metrics.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_cache_reap_metrics.conf`; stream reaper on the main port + `/metrics` HTTP server via `extra_ports={"METRICS_PORT"}`; export + cache-state roots seeded under `tmp_path` for parse-time validation, cinfo planter build unchanged); 1/1 pass.
- [x] `tests/test_webdav_lock_startup_sweep.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_webdav_lock_startup_sweep.conf`; per-test `_spec(root, sweep)` seeds lock xattrs before `start()` so the worker-startup sweep is observed on disk; the `nginx -t` case uses `register`+`render_nginx`+`nginx_test`; export root seeded under `tmp_path`); 3/3 pass.

### Auth, Token, S3, WebDAV

- [x] `tests/test_token_aud_array.py` — migrated 2026-07-16 to `LifecycleHarness` (shared template `nginx_lc_webdav_token_aud.conf`, protocol `webdav`; `data`/`cadir` + JWKS seeded under `tmp_path`; fixture rebinds module-global `PORT` from `ep.port` to keep test bodies unchanged); 6/6 pass.
- [x] `tests/test_token_es256.py` — migrated 2026-07-16 to `LifecycleHarness` (shares `nginx_lc_webdav_token_aud.conf`; ES256 JWKS seeded under `tmp_path`; fixture yields the EC key and rebinds module-global `PORT`); 3/3 pass.
- [x] `tests/test_macaroon_request.py` — migrated 2026-07-16 to `LifecycleHarness` (shared template `nginx_lc_webdav_macaroon.conf`, protocol `webdav`; `data`/`cadir` seeded, `SECRET_HEX` preserved; fixture rebinds module-global `PORT`/`LOCATION`); 4/4 pass.
- [x] `tests/test_macaroon_negative.py` — migrated 2026-07-16 to `LifecycleHarness` (shares `nginx_lc_webdav_macaroon.conf`; seeds `data`/`cadir`, rebinds `PORT`/`LOCATION`); 5/5 pass.
- [x] `tests/test_s3_list_cache.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_s3_list_cache_self.conf`, protocol `s3`; function-scope gives each test a fresh server, fixture backdates the export-root mtime so the top-level-invalidation test still fires; rebinds module-global `HOST`); 3/3 pass.
- [x] `tests/test_s3_auth_oracle.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_s3_auth_oracle.conf`, protocol `s3`; temp paths under `{TMP_DIR}`, key object seeded under `data`; rebinds module-global `PORT`); 3/3 pass.
- [x] `tests/test_dig.py` — 7/7 green (2026-07-16); WebDAV+JWT dig export via harness.
- [x] `tests/test_host_auth.py` — 2/2 green (2026-07-16); stream host-auth allowlist via harness.
- [x] `tests/test_pwd_auth.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_pwd_auth.conf`, protocol `root`; `data`+`pwd.db` seeded under `tmp_path`; yields `{"url","data"}` with `ep.port`); 5/5 pass.
- [x] `tests/test_native_sss.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_native_sss.conf`, protocol `root`; module-scope `_client_built` split from function-scope `sss_server` that mints the keytab before `start()`); 9/9 pass.
- [x] `tests/test_native_krb5.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_native_krb5.conf`, protocol `root`; KRB5 env threaded via `NginxInstanceSpec.env` for launch + `os.environ` pin for `nginx -t`); 1 pass / 6 skip (client built without `-DBRIX_HAVE_KRB5`; server starts before the skip gate).
- [x] `tests/test_native_gsi_interop.py` — migrated 2026-07-16 to `LifecycleHarness` (template `nginx_lc_native_gsi_interop.conf`, protocol `root`; two function-scope specs `lc-nginx-gsi`/`lc-nginx-gsi-signed`; reuses the `gsi_server` PKI/data fixture, `LD_LIBRARY_PATH` via `spec.env`, URL keeps the cert-CN fqdn); 6/6 pass.
- [x] `tests/test_acc.py` — migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_lc_acc_stream.conf` + `nginx_lc_acc_http_location.conf`; both fixtures function-scope, `data`/`authdb` seeded, `access_log` under `{LOG_DIR}`; audit test reads the harness log dir via a module-level pointer); 10/10 pass.
- [x] `tests/test_acc_residual.py` — migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_lc_acc_residual_stream.conf` + `nginx_lc_acc_residual_webdav.conf`; `_Stream`/`_Webdav` helper classes take `(lifecycle, tmp_path)` and delegate `start()` to the harness; `make_server`/`make_webdav` factory fixtures carry the skip gate); 12/12 pass.

### FRM, Tape, Xfer

- [ ] `tests/test_frm_async.py`
- [ ] `tests/test_frm_staging.py`
- [ ] `tests/test_frm_owner.py`
- [ ] `tests/test_frm_phase1_http.py`
- [ ] `tests/test_frm_phase4.py`
- [ ] `tests/test_frm_phase4_engines.py`
- [ ] `tests/test_frm_control_locality.py`
- [ ] `tests/test_frm_queue.py`
- [ ] `tests/test_frm_scratch.py`
- [ ] `tests/test_tape_rest.py`
- [x] `tests/test_xfer_resume_sweep.py` — 1/1 green (2026-07-16); TTL sweeper via harness (env passed through spec.env).
- [ ] `tests/test_xfer_wt_replay.py`
- [ ] `tests/test_xfer_wt_journal.py`

### Multi-Server Topologies

- [x] `tests/test_proxy_large_read.py` — migrated 2026-07-16 to `LifecycleHarness` (templates `nginx_lc_proxy_large_read_backend.conf` + `nginx_lc_proxy_large_read_proxy.conf`; the proxy spec takes the backend endpoint's port via `template_values`). Unblocked once the underlying splice under-drain stall was fixed in `src/net/proxy/events_splice.c` (`brix_proxy_splice_drain_to_buffered`); 20× single 5 MiB XrdCl reads now finish in ~1.4s total, 1/1 pass. Removed from `LAUNCH_BACKLOG`.
- [ ] `tests/test_tpc_tls.py`
- [ ] `tests/test_tpc_delegation.py`
- [ ] `tests/test_tpc_gsi_nginx_source.py`
- [ ] `tests/test_tpc_gsi_outbound.py`
- [ ] `tests/test_tpc_async_open.py`
- [ ] `tests/test_slice_cache.py`
- [ ] `tests/test_gohep_interop.py`
- [ ] `tests/test_cns.py`
- [ ] `tests/test_cms_fast_settle.py`
- [ ] `tests/test_cms_resilience.py`
- [ ] `tests/test_cms_state_have_select.py`
- [ ] `tests/test_cms_wire_pup_conformance.py`
- [ ] `tests/cms_mesh_lib.py`
- [ ] `tests/test_xrddiag_multiproto.py`
- [ ] `tests/test_xrddiag_compare_davs.py`
- [ ] `tests/test_xrddiag_remote_doctor.py`
- [ ] `tests/test_conformance_topologies.py`
- [ ] `tests/test_xrootd_conformance.py`
- [ ] `tests/official_interop_lib.py`
- [ ] `tests/wlcg_conformance_fleet.py`
- [ ] `tests/mu_authz_lib/fleet.py`

### Evil Actor And Security Suites

- [ ] `tests/test_evil_actor.py`
- [ ] `tests/test_evil_actor_v2.py`
- [ ] `tests/_test_evil_actor_v3_helpers.py`
- [ ] `tests/test_chaos_mixed_auth.py`
- [ ] `tests/test_integrity_matrix.py`
- [ ] `tests/_test_gsi_handshake_helpers.py`
- [ ] `tests/_test_proxy_protocol_edges_helpers.py`
- [ ] `tests/test_root_open_existence_oracle.py`
- [ ] `tests/test_mu_stage_modes.py`
- [ ] `tests/test_mu_cache_serve_authz.py`
- [ ] `tests/test_mu_sidecar_config_guard.py`
- [ ] `tests/test_mu_sidecar_hidden.py`
- [ ] `tests/test_mu_webdav_authz.py`

### I/O Feature Fixtures

- [ ] `tests/test_access_log_batch.py`
- [x] `tests/test_cache_reap_metrics.py` — migrated 2026-07-16 (see the low-risk section above).
- [ ] `tests/test_checksum_on_write.py`
- [ ] `tests/test_crc64.py`
- [ ] `tests/test_pmark.py`
- [ ] `tests/test_put_content_encoding.py`
- [ ] `tests/test_readv_segment_size.py`
- [ ] `tests/test_readv_variable_blocks.py`
- [x] `tests/test_srr_endpoint.py` — 5/5 green (2026-07-16); WLCG SRR document via harness.
- [ ] `tests/test_ssi.py`
- [ ] `tests/test_ssi_config.py`
- [ ] `tests/test_ssi_metrics.py`
- [ ] `tests/test_ssi_wire.py`
- [ ] `tests/test_shutdown_resume.py`
- [ ] `tests/test_mirror_upstream.py`
- [ ] `tests/test_metadata_stress.py`
- [ ] `tests/test_dropin_byte_for_byte.py`
- [ ] `tests/test_native_xrdcp_xrdfs_b.py`
- [ ] `tests/test_libbrix.py`
- [ ] `tests/test_phase51_resilience.py`
- [ ] `tests/_cache_partial_helpers.py`

## Shell Files To Delete After Python Migration

### Convert First

- [x] `tests/run_af_family_conf.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_pblock_pblock.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_credential_http_bearer.sh` - Python replacement exists; migrated test xfailed with same failure as shell; shell deleted 2026-07-16.
- [x] `tests/run_credential_webdav_xroot.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_credential_xroot_gsi.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_dashboard_vfs_browse.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_tpc_fwd_root.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tpc_fwd_live.py` (scenario `tpc-fwd-root`) + `tests/test_cmd_tpc_fwd_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_tpc_fwd_webdav.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tpc_fwd_live.py` (scenario `tpc-fwd-webdav`) + `tests/test_cmd_tpc_fwd_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_storage_backend_metrics.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_storage_backend_schemes.sh` - Python replacement exists; migrated test xfailed on same FRM recall failure as shell; shell deleted 2026-07-16.
- [x] `tests/run_s3_storage_backend.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_s3_store_writable.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_s3_usermeta.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_s3_tape_residency.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tape_live.py` (scenario `s3-tape-residency`) + `tests/test_cmd_tape_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_cache_http_source.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_xroot_origin.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_xroot_webdav_offload.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cachestore_live.py` (scenario `cache-xroot-webdav-offload`) + `tests/test_cmd_cachestore_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_cache_s3_origin.sh` - Python replacement exists; migrated test xfailed on same SigV4 cache-fill failure as shell; shell deleted 2026-07-16.
- [x] `tests/run_cache_backend_source.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_pblock_posix.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_wt_driver.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_watermark.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_watermark_config.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_reaper.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_stage_throttle.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_slice_gsi_legacy.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cache_unit.sh` - Python replacement exists; shell deleted 2026-07-16.

### Credential, Delegation, Auth, Proxy

- [x] `tests/run_credential_xroot_ztn.sh` - Python replacement exists; migrated test xfailed on same token root credential failure as shell; shell deleted 2026-07-16.
- [x] `tests/run_credential_xroot_gsi_writeback.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_credential_wt_ztn.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_credential_dup_warn.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_delegation_twostep.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_delegation_upload.sh` - Ported 2026-07-16 -> `tests/cmdscripts/gsi_trust_live.py` (scenario `delegation-upload`) + `tests/test_cmd_gsi_trust_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_tpc_delegation_nginx.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tpc_fwd_live.py` (scenario `tpc-delegation-nginx`) + `tests/test_cmd_tpc_fwd_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_csi_trust.sh` - Ported 2026-07-16 -> `tests/cmdscripts/gsi_trust_live.py` (scenario `csi-trust`) + `tests/test_cmd_gsi_trust_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_gsi_store_memo.sh` - Ported 2026-07-16 -> `tests/cmdscripts/gsi_trust_live.py` (scenario `gsi-store-memo`) + `tests/test_cmd_gsi_trust_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_gsi_intermediate_ca.sh` - Ported 2026-07-16 -> `tests/cmdscripts/gsi_trust_live.py` (scenario `gsi-intermediate-ca`) + `tests/test_cmd_gsi_trust_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_ktls.sh` - Python replacement exists in `tests/cmdscripts/system_live_ports.py` (`ktls`); shell deleted 2026-07-16.
- [x] `tests/run_tap_proxy.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tap_proxy_live.py` (scenario `tap-proxy`) + `tests/test_cmd_tap_proxy_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_tap_proxy_gsi.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tap_proxy_live.py` (scenario `tap-proxy-gsi`) + `tests/test_cmd_tap_proxy_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_tap_proxy_gsi_hybrid.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tap_proxy_live.py` (scenario `tap-proxy-gsi-hybrid`) + `tests/test_cmd_tap_proxy_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_proxy_env_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_proxy_env_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tap_proxy_live.py` (scenario `proxy-env-live`) + `tests/test_cmd_tap_proxy_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_proxy_metadata_phase.sh` - Python replacement exists in `tests/cmdscripts/system_live_ports.py` (`proxy-metadata-phase`); shell deleted 2026-07-16.
- [x] `tests/run_fwd_brix_brix.sh` - Ported 2026-07-16 -> `tests/cmdscripts/fwd_matrix_live.py` (scenario `fwd-brix-brix`) + `tests/test_cmd_fwd_matrix_live.py`; shell deleted 2026-07-16. NOTE: one inherited FAIL (C HH token cell), xfail'd — fails identically under the shell
- [x] `tests/run_fwd_brix_xrootd.sh` - Ported 2026-07-16 -> `tests/cmdscripts/fwd_matrix_live.py` (scenario `fwd-brix-xrootd`) + `tests/test_cmd_fwd_matrix_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_fwd_xrootd_brix.sh` - Ported 2026-07-16 -> `tests/cmdscripts/fwd_matrix_live.py` (scenario `fwd-xrootd-brix`) + `tests/test_cmd_fwd_matrix_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_user_backend_cred.sh` - Ported 2026-07-16 -> `tests/cmdscripts/user_backend_cred.py` (scenario `base`) + `tests/test_cmd_user_backend_cred.py`; shell deleted 2026-07-16.
- [x] `tests/run_user_backend_cred_root.sh` - Ported 2026-07-16 -> `tests/cmdscripts/user_backend_cred.py` (scenario `root`) + `tests/test_cmd_user_backend_cred.py`; shell deleted 2026-07-16.
- [x] `tests/run_user_backend_cred_ns.sh` - Ported 2026-07-16 -> `tests/cmdscripts/user_backend_cred.py` (scenario `ns`) + `tests/test_cmd_user_backend_cred.py`; shell deleted 2026-07-16.
- [x] `tests/run_user_backend_cred_p2.sh` - Ported 2026-07-16 -> `tests/cmdscripts/user_backend_cred.py` (scenario `p2`) + `tests/test_cmd_user_backend_cred.py`; shell deleted 2026-07-16.
- [x] `tests/run_multiuser_authz.sh` - Ported 2026-07-16 -> `tests/cmdscripts/user_backend_cred.py` (scenario `multiuser-authz`) + `tests/test_cmd_user_backend_cred.py`; shell deleted 2026-07-16.
- [x] `tests/run_cred_metrics.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cred_metrics.py` (scenario `counters`) + `tests/test_cmd_cred_metrics.py`; shell deleted 2026-07-16.
- [x] `tests/fwd_b_token_forward_probe.sh` - Ported 2026-07-16 -> `tests/cmdscripts/fwd_matrix_live.py` (scenario `token-forward-probe`) + `tests/test_cmd_fwd_matrix_live.py`; shell deleted 2026-07-16.

### CVMFS And Brixmount

- [x] `tests/run_cvmfs_catalog_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_classify.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_verify.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_verify.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_bench.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `bench`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_reverse.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `reverse`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_holdopen.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `holdopen`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_proxy.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `proxy`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_manifest.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`manifest`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_minimal.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`minimal`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_resilience.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `resilience`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_conn_reuse.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`connection-reuse`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_stock.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `stock`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_unified_origin.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `unified-origin`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_upstream_metrics.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `upstream-metrics`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_conf_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_core_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_client_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_fetch_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_logging.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `logging`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_select.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `select`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_selectlog.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `selectlog`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_keepalive.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`keepalive`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_failover.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`failover`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_shared_cache.sh` - Direct Python port exists in `tests/cmdscripts/cvmfs_live.py` (`shared-cache`); shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_evict.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `evict`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16. NOTE: 2 inherited FAILs (evict propagation to remote cache store) — fails identically under the shell
- [x] `tests/run_cvmfs_brix_all.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `brix-all`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_cvmfs_faultproxy_bench.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_live_ext.py` (scenario `faultproxy-bench`) + `tests/test_cvmfs_live_ext.py`; shell deleted 2026-07-16.
- [x] `tests/run_mount_cvmfs_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `mount-cvmfs-live`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_brixmount_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_brixmount_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `brixmount-live`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_build.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_check.sh` - Python replacement exists; live check skips when local sockets are sandboxed; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `brixcvmfs-live`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_atlas_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `atlas-live`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_clever_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `clever-live`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_brixcvmfs_overlay.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `overlay`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/cvmfs/run_matrix.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_matrix.py` (scenario `matrix`) + `tests/test_cvmfs_matrix.py`; shell deleted 2026-07-16.
- [x] `tests/cvmfs/run_baselines.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_matrix.py` (scenario `cvmfs-baselines`) + `tests/test_cvmfs_matrix.py`; shell deleted 2026-07-16.
- [x] `tests/cvmfs/spike_cas_hash.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_matrix.py` (scenario `spike-cas-hash`) + `tests/test_cvmfs_matrix.py`; shell deleted 2026-07-16.
- [x] `tests/cvmfs/netem_lab.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_matrix.py` (scenario `netem-lab`) + `tests/test_cvmfs_matrix.py`; shell deleted 2026-07-16.

### Tier, Remote Backend, Stage, Tape, PBlock

- [x] `tests/run_tier_matrix_drivers.sh` - Direct Python port exists in `tests/cmdscripts/tier_matrix_drivers.py`; shell deleted 2026-07-16.
- [x] `tests/run_tier_remote_stage.sh` - Direct Python port exists in `tests/cmdscripts/tier_remote.py` (`remote-stage`); shell deleted 2026-07-16.
- [x] `tests/run_tier_remote_evict.sh` - Direct Python port exists in `tests/cmdscripts/tier_remote.py` (`remote-evict`); shell deleted 2026-07-16.
- [x] `tests/run_tier_remote_store.sh` - Direct Python port exists in `tests/cmdscripts/tier_remote.py` (`remote-store`); shell deleted 2026-07-16.
- [x] `tests/run_tier_sidecar_meta.sh` - Direct Python port exists in `tests/cmdscripts/tier_remote.py` (`sidecar-meta`); shell deleted 2026-07-16.
- [x] `tests/run_tier_slice_fill.sh` - Direct Python port exists in `tests/cmdscripts/tier_remote.py` (`slice-fill`); shell deleted 2026-07-16.
- [x] `tests/run_tier_instance_lifetime.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tier_stage_live.py` (scenario `tier-instance-lifetime`) + `tests/test_cmd_tier_stage_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_remote_backend_serve_offload.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`serve-offload`); shell deleted 2026-07-16.
- [x] `tests/run_remote_backend_meta.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`meta`); shell deleted 2026-07-16.
- [x] `tests/run_remote_backend_write.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`stream-write`); shell deleted 2026-07-16.
- [x] `tests/run_remote_backend_staging.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`staging`); shell deleted 2026-07-16.
- [x] `tests/run_remote_backend_webdav.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`webdav`); shell deleted 2026-07-16.
- [x] `tests/run_stage_reconcile.sh` - Direct Python port exists in `tests/cmdscripts/remote_backend.py` (`stage-reconcile`); shell deleted 2026-07-16.
- [x] `tests/run_stage_async_remote_flush.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tier_stage_live.py` (scenario `stage-async-remote-flush`) + `tests/test_cmd_tier_stage_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_root_stage_writeback.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tier_stage_live.py` (scenario `root-stage-writeback`) + `tests/test_cmd_tier_stage_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_root_slice_fill.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tier_stage_live.py` (scenario `root-slice-fill`) + `tests/test_cmd_tier_stage_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_tape_recall_stream.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tape_live.py` (scenario `tape-recall-stream`) + `tests/test_cmd_tape_live.py`; shell deleted 2026-07-16. NOTE: inherited server double-free crash — fails identically under the shell
- [x] `tests/run_tape_recall_async.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tape_live.py` (scenario `tape-recall-async`) + `tests/test_cmd_tape_live.py`; shell deleted 2026-07-16. NOTE: inherited server double-free crash — fails identically under the shell
- [x] `tests/run_tape_exec_adapter.sh` - Ported 2026-07-16 -> `tests/cmdscripts/tape_live.py` (scenario `tape-exec-adapter`) + `tests/test_cmd_tape_live.py`; shell deleted 2026-07-16. NOTE: inherited server double-free crash — fails identically under the shell
- [x] `tests/run_pblock_meta_gsi.sh` - Ported 2026-07-16 -> `tests/cmdscripts/pblock_live.py` (scenario `pblock-meta-gsi`) + `tests/test_cmd_pblock_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_pblock_writethrough.sh` - Ported 2026-07-16 -> `tests/cmdscripts/pblock_live.py` (scenario `pblock-writethrough`) + `tests/test_cmd_pblock_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_pblock_root.sh` - Ported 2026-07-16 -> `tests/cmdscripts/pblock_live.py` (scenario `pblock-root`) + `tests/test_cmd_pblock_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_pblock_webdav.sh` - Ported 2026-07-16 -> `tests/cmdscripts/pblock_live.py` (scenario `pblock-webdav`) + `tests/test_cmd_pblock_live.py`; shell deleted 2026-07-16.

### X509, Token, Client, Load, Misc

- [x] `tests/run_token_conformance.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_token_differential.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_x509_differential.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_x509_matrix_differential.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_official_xrootd_tests.sh` - Ported 2026-07-16 -> `tests/cmdscripts/official_interop.py` (scenario `noauth/host/stress/all`) + `tests/test_cmd_official_interop.py`; shell deleted 2026-07-16.
- [x] `tests/run_cross_compatible_tests.sh` - Ported 2026-07-16 -> `tests/cmdscripts/official_interop.py` (scenario `cross-compatible`) + `tests/test_cmd_official_interop.py`; shell deleted 2026-07-16.
- [x] `tests/run_client_features.sh` - Ported 2026-07-16 -> `tests/cmdscripts/client_features.py` (scenario `12 scenarios + all`) + `tests/test_cmd_client_features.py`; shell deleted 2026-07-16.
- [x] `tests/run_http_store_writable.sh` - Direct Python port exists in `tests/cmdscripts/http_store_writable.py`; shell deleted 2026-07-16.
- [x] `tests/run_unified_conf.sh` - Python replacement exists in `tests/cmdscripts/unified_conf.py`; shell deleted 2026-07-16.
- [x] `tests/run_overlay_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_ucred_conf.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_io_uring_backend.sh` - Python replacement exists in `tests/cmdscripts/system_live_ports.py` (`io-uring-backend`); shell deleted 2026-07-16.
- [x] `tests/run_load_test.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/run_xroot_cachestore_serve.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cachestore_live.py` (scenario `xroot-cachestore-serve`) + `tests/test_cmd_cachestore_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_cachestore_sidecar.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cachestore_live.py` (scenario `cachestore-sidecar`) + `tests/test_cmd_cachestore_live.py`; shell deleted 2026-07-16. NOTE: inherited sd_cache cinfo I/O-error failure — original shell hangs (RC=124) with identical warnings
- [x] `tests/run_xmeta.sh` - Python replacement exists in `tests/cmdscripts/metadata_live_ports.py` (`xmeta`); shell deleted 2026-07-16.
- [x] `tests/run_nonstaged_reap.sh` - Python replacement exists in `tests/cmdscripts/metadata_live_ports.py` (`nonstaged-reap`); shell deleted 2026-07-16.
- [x] `tests/run_scvmfs.sh` - Ported 2026-07-16 -> `tests/cmdscripts/brixcvmfs_live.py` (scenario `scvmfs`) + `tests/test_cmd_brixcvmfs_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_transparent_relay.sh` - Ported 2026-07-16 -> `tests/cmdscripts/fwd_matrix_live.py` (scenario `transparent-relay`) + `tests/test_cmd_fwd_matrix_live.py`; shell deleted 2026-07-16.
- [x] `tests/run_xfer_audit_sink.sh` - Python replacement exists in `tests/cmdscripts/metadata_live_ports.py` (`xfer-audit-sink`); shell deleted 2026-07-16.
- [x] `tests/run_cache_af_family.sh` - Python replacement exists in `tests/cmdscripts/system_live_ports.py` (`cache-af-family`); shell deleted 2026-07-16.
- [x] `tests/run_sd_s3_meta.sh` - Python replacement exists in `tests/cmdscripts/metadata_live_ports.py` (`sd-s3-meta`); shell deleted 2026-07-16.
- [x] `tests/demo_dashboard_live.sh` - Ported 2026-07-16 -> `tests/cmdscripts/dashboard_demo_live.py` (scenario `demo flow`) + `tests/test_cmd_dashboard_demo_live.py`; shell deleted 2026-07-16.
- [x] `tests/profile_lifecycle.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/profile_load.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph_harness.sh` - Ported 2026-07-16 -> `tests/cmdscripts/ceph_harness.py` (scenario `start/stop/status/env/pool-reset`) + `tests/test_ceph_harness.py`; shell deleted 2026-07-16.
- [x] `tests/frm_fake_mss.sh` - Python replacement exists in `tests/cmdscripts/frm_fake_mss.py`; shell deleted 2026-07-16.

### Static, Lint, Build, And Suite Entrypoints

- [x] `tests/lint_alloc.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/lint_loc.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/build_dynamic_modules.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/build_sanitizer.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/run_suite.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/brutal_teardown.sh` - Python replacement exists; shell deleted 2026-07-16.
- [ ] `tests/manage_test_servers.sh` - Python replacement exists in `tests/cmdscripts/manage_test_servers.py`; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).

### C, Unit, Fuzz, Ceph Shells

- [x] `tests/c/run_vfs_caps_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_sesslog_tests.sh` - Python replacement exists; migrated test xfailed on same current-API compile failure as shell; shell deleted 2026-07-16.
- [x] `tests/c/run_cache_lock_reclaim_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_flush_deadletter.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_shm_mutex_recovery_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_ratelimit_gauge_reset_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_delegation_store.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_fs_usage_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_slice_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_pblock_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_site_n2n_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_mu_unit.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_x509_conformance_tests.sh` - Python replacement exists; migrated test xfailed on same current link failure as shell; shell deleted 2026-07-16.
- [x] `tests/c/run_signing_policy_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/test_xrdcinfo.sh` - Python replacement exists; migrated test xfailed on same cinfo magic failure as shell; shell deleted 2026-07-16.
- [x] `tests/c/run_cred_mint.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_ucred_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_stage_reconcile_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_sd_ceph_compat_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_meta_advisory_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_compression_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_cache_admit_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_stage_admit_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_cache_storage_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_vo_token_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_cinfo_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_x509_oracle.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_sreq_compat.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/c/run_sd_remote_wrongkind_tests.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/unit/run_tests.sh` - Python replacement exists; migrated test xfailed on same `test_xml_compat.c` link failure as shell; shell deleted 2026-07-16.
- [x] `tests/fuzz/run_all.sh` - Python replacement exists; shell deleted 2026-07-16.
- [x] `tests/ceph/build_in_container.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_striper_migrate.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_rescue_tools.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_cephfs_ro_live.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/ceph_export_smoke.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_py_migrate.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_sd_ceph_cred_live.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/cephfs_ro_smoke.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.
- [x] `tests/ceph/run_sd_ceph_live.sh` - Python replacement exists; execution opt-in; shell deleted 2026-07-16.

### Shell Libraries To Port And Delete

- [ ] `tests/lib/tpc_fwd.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/xrdhttp.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/dedicated.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/fwd_matrix.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/util.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/pki.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/nginx.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [ ] `tests/lib/refxrootd.sh` - Python replacement exists; KEPT deliberately (compatibility fleet backend, excluded from the 2026-07-16 deletion sweep).
- [x] `tests/guard/run_guard_core.sh` - Python replacement exists; shell deleted 2026-07-16.

Replacement modules:

- [x] `tests/lib_py/tpc_fwd.py`
- [x] `tests/lib_py/xrdhttp.py`
- [x] `tests/lib_py/dedicated.py`
- [x] `tests/lib_py/fwd_matrix.py`
- [x] `tests/lib_py/pki.py`
- [x] `tests/lib_py/nginx.py`
- [x] `tests/lib_py/refxrootd.py`
- [x] `tests/cmdscripts/manage_test_servers.py`
- [x] `tests/cmdscripts/userns_run.py`
- [x] `tests/cmdscripts/frm_fake_mss.py`
- [x] `tests/cmdscripts/live_common.py`
- [x] `tests/cmdscripts/cvmfs_verify.py`
- [x] `tests/cmdscripts/tier_matrix_drivers.py`
- [x] `tests/cmdscripts/http_store_writable.py`
- [x] `tests/cmdscripts/tier_remote.py`
- [x] `tests/cmdscripts/cvmfs_live.py`
- [x] `tests/cmdscripts/remote_backend.py`
- [ ] `tests/lib_py/guard_core.py`

## Per-File Migration Checklist

For every checked target above:

- [ ] Identify whether it needs server lifecycle, command-line clients only, or pure static/build behavior.
- [ ] Move any inline nginx config to `tests/configs/`.
- [ ] Add one or more `NginxInstanceSpec` registrations.
- [ ] Replace direct port constants with registry endpoint lookup or documented fixed fleet endpoints.
- [ ] Move temp dirs under `$TEST_ROOT/registry/<name>` or pytest `tmp_path`.
- [ ] Replace shell cleanup traps with registry teardown.
- [ ] Preserve command-line invocation and output assertions.
- [ ] Add skip behavior for missing optional external tools.
- [ ] Add xdist-safe data seeding.
- [ ] Add runtime verification or `py_compile` check.
- [ ] Update docs if an operator-facing command changes.
- [ ] Delete the shell file after Python parity exists.

## Detailed File Change Matrix

### Harness And Core Registry Files

- [x] `tests/server_registry.py`
  - [x] Add `@dataclass(frozen=True) NginxInstanceSpec`.
  - [x] Add `@dataclass(frozen=True) CommandSpec` for former shell command flows.
  - [x] Add process-independent global registry populated at module import time.
  - [x] Add duplicate-name detection with file/line diagnostics.
  - [x] Add `register_nginx`, `register_xrootd`, `register_command_suite`.
  - [x] Add `server(name)` lookup for tests.
  - [x] Add `manifest_write(path)` and `manifest_read(path)`.
  - [x] Add `selected_specs(pytest_items)` dependency closure.
  - [x] Wire `selected_specs(pytest_items)` into session startup so only collected tests start their needed servers.

- [x] `tests/server_launcher.py`
  - [x] Add `render_nginx(spec)`.
  - [x] Add `nginx_test(spec)` with captured stdout/stderr.
  - [x] Add `start_nginx(spec)` and `stop_nginx(instance)`.
  - [x] Add lifecycle calls: reload, reopen, restart, kill worker, process snapshot.
  - [x] Add readiness probes for root, WebDAV, S3, metrics, CMS, and raw TCP.
  - [x] Add `run_cmd(argv, *, env=None, timeout=..., input=None)` wrapper used by command tests.
  - [x] Add structured failure object that includes config path, logs, command, rc, and output tail.

- [x] `tests/cmdscripts/__init__.py`
  - [x] Export shared helpers for former shell tests.
  - [x] Export `main()` helper for optional direct `python -m tests.cmdscripts.<name>` debugging.
  - [x] Keep all logic importable by pytest; no shell wrapper required.

- [x] `tests/test_server_registry_smoke.py`
  - [x] Register a one-port nginx from a committed config template.
  - [x] Assert manifest lookup returns host, port, prefix, config, data root.
  - [x] Assert selected manifests include only requested specs.
  - [x] Assert xdist worker can read the manifest without starting a process.
  - [x] Assert launcher failure reports and command-script helpers are importable.

- [x] `tests/test_server_registry_lint.py` — 7 tests, all green (2026-07-16)
  - [x] Fail on `*.sh` anywhere under `tests/` — except the compat-fleet backend `manage_test_servers.sh` and its sourced `tests/lib/*.sh` helpers (`test_shell_tests_fully_ported_except_fleet_backend`).
  - [x] Fail on unregistered `subprocess.Popen([NGINX...])` — `test_no_new_direct_nginx_launches`, enforced against strictly-shrinking `LAUNCH_BACKLOG`.
  - [x] Fail on unregistered `subprocess.run([NGINX...])` start/stop/reload — same `_LAUNCH` scan + `test_launch_backlog_only_shrinks` (backlog can only lose entries).
  - [x] Fail on inline nginx heredocs or multiline strings containing `events {` plus `stream {`/`http {` — `test_no_new_inline_nginx_configs` + `test_inline_config_backlog_only_shrinks` against strictly-shrinking `INLINE_CONFIG_BACKLOG` (catches `test_evil_paths.py`, which launches via a lowercase `nginx_bin` local the NGINX-token scan misses).
  - [x] Fail on new test code importing shell helpers — `test_no_test_code_sources_shell_helpers` (subprocess invoking `manage_test_servers.sh`/`lib/*.sh`).
  - [x] Allow `subprocess.run` for command-line clients only through `registry.run_cmd` or command helpers — launch scan is scoped to the nginx binary token, so client `run_cmd`/xrdcp/xrdfs/curl invocations are never flagged.

- [x] `tests/configs/nginx_registry_smoke.conf`
  - [x] Add smallest possible config using placeholders for port, data root, and logs.
  - [x] Use no domain-specific module features beyond anonymous root read.

- [x] `tests/configs/REGISTRY_MIGRATION.md`
  - [x] Explain how to add a new registry-backed server.
  - [x] Explain how to port a former shell script.
  - [x] Document naming convention for `tests/cmdscripts/*.py`.
  - [x] Document that `.sh` files are forbidden after this phase.

### Existing Harness Files

- [x] `tests/conftest.py`
  - [x] Import registry during pytest configuration.
  - [x] Add `pytest_collection_modifyitems` pass that records specs needed by collected tests.
  - [x] Register `registry_server` and `registry_servers` markers.
  - [x] Start registry specs in controller `pytest_sessionstart` after `_setup_session` seeds data/PKI.
  - [x] Write `$TEST_ROOT/registry/manifest.json`.
  - [x] In xdist workers, read manifest and skip all starts.
  - [x] Add `registry_server` fixture returning endpoint metadata.
  - [x] Add `command_runner` fixture wrapping `registry.run_cmd`.
  - [x] Ensure teardown stops selected registry instances before shared tree removal.

- [x] `tests/settings.py`
  - [x] Add `REGISTRY_ROOT = os.path.join(TEST_ROOT, "registry")`.
  - [x] Add `REGISTRY_MANIFEST = os.path.join(REGISTRY_ROOT, "manifest.json")`.
  - [x] Add `TEST_REGISTRY_START=0/1` override.
  - [x] Add `TEST_REGISTRY_KEEP_LOGS=1` override.
  - [x] Add `REGISTRY_PORT_BASE` only for tests that require stable port bands.
  - [x] Keep dynamic ports default for newly migrated tests.

- [x] `tests/config_templates.py`
  - [x] Add strict placeholder validation.
  - [x] Add `render_config_to_path(name, dest, **values)`.
  - [x] Keep backward compatibility for already migrated tests during transition.
  - [x] Make registry use strict mode by default.

- [x] `TESTING.md`
  - [ ] Replace shell runner examples with `pytest ...` or `python -m tests.cmdscripts...`.
  - [x] Document zero-shell rule.
  - [x] Document how command-line tool tests are written in Python.
  - [x] Document registry logs and manifest paths.

- [ ] `README.md`
  - [ ] Replace references to `tests/run_*.sh` with pytest/Python entry points.
  - [x] Link to `tests/configs/REGISTRY_MIGRATION.md`.

### Python Test File Edit Recipes

Apply the matching recipe to every Python file listed in `Python Migration Targets`.

- [ ] Single-server files
  - [ ] Delete module/session fixture that writes config and starts nginx.
  - [ ] Add module-level `register_nginx(NginxInstanceSpec(...))`.
  - [ ] Replace fixture return value with `registry_server("<name>")`.
  - [ ] Move seed data into a fixture that writes under returned `data_root`.
  - [ ] Replace hard-coded local port with returned endpoint.

- [ ] Auth/token/S3/WebDAV files
  - [ ] Register auth material as `requires=["pki", "tokens"]` or explicit setup callback.
  - [ ] Keep JWT/cert/key generation in Python fixtures.
  - [ ] Register HTTP/WebDAV/S3 ports through `extra_ports`.
  - [ ] Use `registry.run_cmd` for `curl`, `xrdcp`, `xrdfs`, `openssl`, and native clients.

- [ ] FRM/tape/xfer files
  - [ ] Register each staging/queue/tape backend as a named spec.
  - [ ] Move fake MSS scripts into Python helpers where possible.
  - [ ] Represent queue/journal paths in `template_values`.
  - [ ] Use lifecycle harness restart primitive for durability tests.

- [ ] Multi-server topology files
  - [ ] Register one spec per node with explicit `requires`.
  - [ ] Use endpoint interpolation from dependency specs instead of free-form strings.
  - [ ] Start all nodes in dependency order before tests.
  - [ ] Expose topology object fixture with named endpoints.
  - [ ] Keep per-test data isolation by subdirectory or unique object names.

- [ ] Evil actor/security files
  - [ ] Register attack target servers centrally.
  - [ ] Keep malicious client behavior in test bodies.
  - [ ] Use lifecycle primitives for crash/restart assertions.
  - [ ] Ensure every spawned attack helper has timeout and captured output.

- [ ] I/O feature files
  - [ ] Register the feature-specific config.
  - [ ] Replace manual log path plumbing with registry metadata.
  - [ ] Store generated payloads under `tmp_path` or registry data root.
  - [ ] Use registry log paths for assertions about audit/metrics/reaper behavior.

### Shell File Replacement Rules

Every `.sh` file listed in `Shell Files To Delete After Python Migration` follows this exact migration rule:

- [ ] Create `tests/cmdscripts/<stem>.py`, where `<stem>` is the shell filename without `.sh` and without a leading `run_` when that reads better.
- [ ] Add a pytest test module when the command flow should be collected by the suite:
  - [ ] `tests/test_cmd_<stem>.py` for normal command suites.
  - [ ] `tests/test_cvmfs_<stem>.py` for CVMFS command suites.
  - [ ] `tests/test_ceph_<stem>.py` for Ceph command suites.
  - [ ] `tests/test_c_<stem>.py` for C helper runners.
- [ ] Move any nginx config body to `tests/configs/<stem>.conf`.
- [ ] Move any reusable shell function to `tests/lib_py/<domain>.py`.
- [ ] Replace `trap cleanup` with registry teardown and pytest `tmp_path`.
- [ ] Replace `set -euo pipefail` control flow with Python assertions and explicit error messages.
- [ ] Replace `mktemp` with `tmp_path` or `tempfile.TemporaryDirectory(dir=TMP_DIR)`.
- [ ] Replace `"$NGINX" ...` with registry specs and launcher calls.
- [ ] Replace command-line client calls with `registry.run_cmd([...])`.
- [ ] Delete the original `.sh` file.

Concrete naming examples:

- [x] `tests/run_af_family_conf.sh` -> `tests/cmdscripts/af_family_conf.py` + `tests/test_cmd_af_family_conf.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_pblock_pblock.sh` -> `tests/cmdscripts/cache_pblock_pblock.py` + `tests/test_cmd_cache_pblock_pblock.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_http_bearer.sh` -> `tests/cmdscripts/credential_http_bearer.py` + `tests/test_cmd_credential_http_bearer.py`.
  - [ ] Fix inherited authenticated-fill failure / remove xfail.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_webdav_xroot.sh` -> `tests/cmdscripts/credential_webdav_xroot.py` + `tests/test_cmd_credential_webdav_xroot.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_xroot_gsi.sh` -> `tests/cmdscripts/credential_xroot_gsi.py` + `tests/test_cmd_credential_xroot_gsi.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_dashboard_vfs_browse.sh` -> `tests/cmdscripts/dashboard_vfs_browse.py` + `tests/test_cmd_dashboard_vfs_browse.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_storage_backend_metrics.sh` -> `tests/cmdscripts/storage_backend_metrics.py` + `tests/test_cmd_storage_backend_metrics.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_storage_backend_schemes.sh` -> `tests/cmdscripts/storage_backend_schemes.py` + `tests/test_cmd_storage_backend_schemes.py`.
  - [ ] Fix inherited FRM recall failure / remove xfail.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_s3_usermeta.sh` -> `tests/cmdscripts/s3_usermeta.py` + `tests/test_cmd_s3_usermeta.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_s3_store_writable.sh` -> `tests/cmdscripts/s3_store_writable.py` + `tests/test_cmd_s3_store_writable.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_s3_storage_backend.sh` -> `tests/cmdscripts/s3_storage_backend.py` + `tests/test_cmd_s3_storage_backend.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_http_source.sh` -> `tests/cmdscripts/cache_http_source.py` + `tests/test_cmd_cache_http_source.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_xroot_origin.sh` -> `tests/cmdscripts/cache_xroot_origin.py` + `tests/test_cmd_cache_xroot_origin.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_s3_origin.sh` -> `tests/cmdscripts/cache_s3_origin.py` + `tests/test_cmd_cache_s3_origin.py`.
  - [ ] Fix inherited SigV4 cache-fill failure / remove xfail.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_backend_source.sh` -> `tests/cmdscripts/cache_backend_source.py` + `tests/test_cmd_cache_backend_source.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_pblock_posix.sh` -> `tests/cmdscripts/cache_pblock_posix.py` + `tests/test_cmd_cache_pblock_posix.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_wt_driver.sh` -> `tests/cmdscripts/cache_wt_driver.py` + `tests/test_cmd_cache_wt_driver.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_watermark.sh` -> `tests/cmdscripts/cache_watermark.py` + `tests/test_cmd_cache_watermark.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_watermark_config.sh` -> `tests/cmdscripts/cache_watermark_config.py` + `tests/test_cmd_cache_watermark_config.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_reaper.sh` -> `tests/cmdscripts/cache_reaper.py` + `tests/test_cmd_cache_reaper.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_stage_throttle.sh` -> `tests/cmdscripts/cache_stage_throttle.py` + `tests/test_cmd_cache_stage_throttle.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_slice_gsi_legacy.sh` -> `tests/cmdscripts/cache_slice_gsi_legacy.py` + `tests/test_cmd_cache_slice_gsi_legacy.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_cache_unit.sh` -> `tests/cmdscripts/cache_unit.py` + `tests/test_cmd_cache_unit.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_xroot_ztn.sh` -> `tests/cmdscripts/credential_xroot_ztn.py` + `tests/test_cmd_credential_xroot_ztn.py`.
  - [ ] Fix inherited token root credential failure / remove xfail.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_xroot_gsi_writeback.sh` -> `tests/cmdscripts/credential_xroot_gsi_writeback.py` + `tests/test_cmd_credential_xroot_gsi_writeback.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_wt_ztn.sh` -> `tests/cmdscripts/credential_wt_ztn.py` + `tests/test_cmd_credential_wt_ztn.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_credential_dup_warn.sh` -> `tests/cmdscripts/credential_dup_warn.py` + `tests/test_cmd_credential_dup_warn.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/run_delegation_twostep.sh` -> `tests/cmdscripts/delegation_twostep.py` + `tests/test_cmd_delegation_twostep.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/cvmfs/run_matrix.sh` - Ported 2026-07-16 -> `tests/cmdscripts/cvmfs_matrix.py` (scenario `matrix`) + `tests/test_cvmfs_matrix.py`; shell deleted 2026-07-16.
- [x] `tests/c/run_vfs_caps_tests.sh` -> `tests/cmdscripts/c_object_units.py` + `tests/test_c_object_units.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/ceph/run_sd_ceph_live.sh` -> `tests/cmdscripts/ceph_operator.py` (scenario `sd_ceph_live`) + `tests/test_cmd_ceph_operator.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/unit/run_tests.sh` -> `tests/cmdscripts/unit_tests.py` + `tests/test_cmd_unit_tests.py`.
  - [x] Delete shell. (2026-07-16)
- [x] `tests/fuzz/run_all.sh` -> `tests/cmdscripts/fuzz_all.py` + `tests/test_cmd_fuzz_all.py`.
  - [x] Delete shell. (2026-07-16)

### Shell Library Replacement Rules

- [ ] `tests/lib/util.sh` -> `tests/lib_py/util.py`
  - [ ] Port command discovery, port probing, process cleanup, and rendering helpers.
  - [ ] Delete sed-based template rendering once Python strict rendering is used everywhere.

- [ ] `tests/lib/nginx.sh` -> `tests/lib_py/nginx.py`
  - [ ] Port nginx command construction, start, stop, force-stop, status, readiness.
  - [ ] Delete direct shell lifecycle implementation.

- [ ] `tests/lib/dedicated.sh` -> `tests/lib_py/dedicated.py`
  - [ ] Port dedicated fleet definitions to `NginxInstanceSpec` factories.
  - [ ] Delete `start_all_dedicated` shell logic after conftest owns registry startup.

- [ ] `tests/lib/refxrootd.sh` -> `tests/lib_py/refxrootd.py`
  - [ ] Port reference xrootd config rendering, start, stop, readiness.
  - [ ] Register reference servers through the same manifest.

- [ ] `tests/lib/pki.sh` -> `tests/lib_py/pki.py`
  - [ ] Port CA/cert/proxy/VOMS generation.
  - [ ] Expose idempotent Python setup function used by conftest.

- [ ] `tests/lib/xrdhttp.sh` -> `tests/lib_py/xrdhttp.py`
  - [ ] Port XrdHttp reference-server setup.
  - [ ] Replace current direct script launch in conftest/fleet setup.

- [ ] `tests/lib/tpc_fwd.sh` -> `tests/lib_py/tpc_fwd.py`
  - [ ] Port TPC forwarding matrix helpers.
  - [ ] Expose command-suite helpers for former TPC shell tests.

- [ ] `tests/lib/fwd_matrix.sh` -> `tests/lib_py/fwd_matrix.py`
  - [ ] Port matrix expansion and expected-result logic.

- [x] `tests/guard/run_guard_core.sh` -> `tests/cmdscripts/guard_core.py` + `tests/test_cmd_guard_core.py`
  - [x] Compile/run guard helper from Python.
  - [x] Delete shell runner. (2026-07-16)

## Per-File Action Ledger

This ledger is the implementation contract. Every row must end with either a migrated Python file or a deleted shell file. No `.sh` file is allowed to remain under `tests/`.

### Core Harness Ledger

| File | Required changes | Completion check |
|---|---|---|
| `tests/conftest.py` | Import registry, collect selected specs, start registry before test bodies, expose `registry_server` and `command_runner`, stop registry at teardown, read manifest in xdist workers. | `pytest tests/test_server_registry_smoke.py -q` passes in normal and xdist mode. |
| `tests/settings.py` | Add registry root/manifest/env flags, keep dynamic ports default, add stable port helpers only where needed. | `python -m py_compile tests/settings.py`. |
| `tests/config_templates.py` | Add strict placeholder validation and `render_config_to_path`; keep old `render_config` during migration. | Unit test proves unresolved `{PLACEHOLDER}` fails in strict mode. |
| `tests/server_registry.py` | New registry model/API, manifest I/O, selected-spec resolution, duplicate detection. | Smoke test validates registration, manifest write/read, xdist worker read path. |
| `tests/server_launcher.py` | New nginx/xrootd lifecycle and command runner implementation. | Smoke test starts/stops nginx and captures logs on failure. |
| `tests/test_server_registry_lint.py` | New lint test banning `.sh`, inline nginx configs, and direct unmanaged nginx subprocess starts. | Lint test fails before final deletion, then passes when zero shell remains. |
| `tests/cmdscripts/__init__.py` | Shared helpers for command-suite Python replacements. | `python -m py_compile tests/cmdscripts/__init__.py`. |
| `tests/lib_py/*.py` | Python replacements for every shell helper under `tests/lib/`. | `python -m py_compile tests/lib_py/*.py`. |
| `tests/manage_test_servers.sh` | Port behavior into Python registry/fleet entry point, then delete shell file. | `test_server_registry_lint.py` confirms file absent. |
| `tests/lib/*.sh` | Port each helper to `tests/lib_py/<name>.py`, update imports, then delete shell file. | No `tests/lib/*.sh` files remain. |
| `README.md` | Replace shell test runner references with pytest/Python commands. | `rg "run_.*\\.sh|manage_test_servers\\.sh" README.md` returns no stale runner docs. |
| `TESTING.md` | Document registry usage, zero-shell policy, command-runner pattern, logs/manifest paths. | `rg "run_.*\\.sh|\\.sh" TESTING.md` has no test-runner instructions. |

### Lifecycle Python Files Ledger

| File | Required changes | Completion check |
|---|---|---|
| `tests/test_reload.py` | Replace local `Instance` process management with lifecycle harness calls: `start`, `reload`, `reopen`, `expect_config_failure`, `stop`. Move valid config to `tests/configs/nginx_reload_instance.conf`; keep invalid config as strict negative fixture or template. | Existing reload tests pass; no direct `NGINX_BIN` subprocess starts remain. |
| `tests/test_lifecycle_speed.py` | Register lifecycle benchmark server specs; replace ad hoc start/stop with harness timing wrappers. Move config to `tests/configs/nginx_lifecycle_speed.conf`. | Test still measures start/reload/stop timing through Python harness. |
| `tests/test_shm_fork_safety.py` | Replace manual worker kill/restart with `registry.kill_worker` and `process_snapshot`; move configs to templates. | Fork-safety assertions still inspect worker replacement. |
| `tests/test_phase22_health_check.py` | Convert live health-check servers to registry specs; config-validation negatives use `expect_config_failure`. | All health-check tests run under pytest harness only. |
| `tests/test_phase21_proxy_filter.py` | Register WebDAV/introspection fixtures as specs; move generated configs to templates; use registry endpoints in tests. | No `Popen([NGINX_BIN...])`; proxy-filter tests pass. |
| `tests/test_phase23_admin_api.py` | Register admin API instance(s); move generated config to template; replace manual Popen/cleanup. | Admin API tests use `registry_server`. |
| `tests/test_phase24_mirror.py` | Register each mirror scenario as a named spec; move inline configs to templates; use registry log metadata for shadow assertions. | Mirror tests pass without local nginx starts. |
| `tests/test_phase25_ratelimit.py` | Register rate-limit server spec; config validation uses strict negative helper. | Rate-limit tests pass through registry lifecycle. |
| `tests/userns/e2e_redteam.py` | Convert script-style flow into pytest module using `registry.run_privileged_step`; no shell launcher. | Privileged tests skip cleanly when userns prerequisites absent. |
| `tests/userns/run.sh` | Port to `tests/userns/test_userns_runner.py` or existing userns pytest modules; delete shell. | No `tests/userns/*.sh` remains. |
| `tests/valgrind/run_valgrind.sh` | Port to `tests/cmdscripts/valgrind_run.py` plus `tests/test_cmd_valgrind_run.py`; invoke valgrind via `run_cmd`. Delete shell. | Valgrind workflow is a pytest target. |
| `tests/build_dynamic_modules.sh` | Port to `tests/cmdscripts/build_dynamic_modules.py` plus pytest test; delete shell. | Build test runs through pytest. |
| `tests/build_sanitizer.sh` | Port to `tests/cmdscripts/build_sanitizer.py` plus pytest test; delete shell. | Sanitizer build target runs through pytest. |
| `tests/brutal_teardown.sh` | Replace with Python cleanup command `python -m tests.cmdscripts.brutal_teardown`; delete shell. | Cleanup command works and lint sees no shell. |
| `tests/run_suite.sh` | Replace with documented pytest invocations or `python -m tests.cmdscripts.run_suite`; delete shell. | Suite entrypoint is Python-only. |

### Python Test Families Ledger

| Files | Required changes | Completion check |
|---|---|---|
| Client/xrdiag single-server files | `test_client_xrd_frontend.py`, `test_client_xrd_doctor_login.py`, `test_client_xrdrc_alias.py`, `test_client_xrdfs_tools.py`, `test_client_xrdcp_bulk.py`, `test_xrd_busybox.py`, `test_xrdmapc.py`, `test_xrddiag.py`, `test_xrddiag_capture.py`, `test_xrddiag_watch.py`, `test_xrddiag_probe.py`, `test_native_client_diagnostics.py`: delete local nginx fixtures, register `nginx_stream_posix_anon.conf`-style spec, use `registry_server`. | `rg "Popen\\(\\[NGINX|run\\(\\[NGINX" <files>` returns none except lifecycle helper imports. |
| Dashboard/guard files | `test_dashboard_config_anon.py`, `test_dashboard_files.py`, `test_storage_backend_panel.py`, `test_scan.py`, `test_arc_guard.py`, `test_guard_endpoints.py`, `test_xrdhttp_guard.py`, `test_stream_guard.py`, `test_netfault_stream.py`: register HTTP/stream specs, move configs to templates, use registry log paths. | Each module passes standalone under pytest. |
| Auth/token/S3/WebDAV files | `test_token_aud_array.py`, `test_token_es256.py`, `test_macaroon_request.py`, `test_macaroon_negative.py`, `test_s3_list_cache.py`, `test_s3_auth_oracle.py`, `test_dig.py`, `test_host_auth.py`, `test_pwd_auth.py`, `test_native_sss.py`, `test_native_krb5.py`, `test_native_gsi_interop.py`, `test_acc.py`, `test_acc_residual.py`: register auth-capable specs; publish token/cert paths in metadata; call clients with `run_cmd`. | No manual nginx lifecycle; auth artifacts still regenerated by Python setup. |
| FRM/tape/xfer files | `test_frm_async.py`, `test_frm_staging.py`, `test_frm_owner.py`, `test_frm_phase1_http.py`, `test_frm_phase4.py`, `test_frm_phase4_engines.py`, `test_frm_control_locality.py`, `test_frm_queue.py`, `test_frm_scratch.py`, `test_tape_rest.py`, `test_xfer_resume_sweep.py`, `test_xfer_wt_replay.py`, `test_xfer_wt_journal.py`: register queue/staging/tape specs; port fake MSS shell to Python; use restart primitive for durability. | FRM/tape tests pass or skip based on module availability, not config-generation failure. |
| TPC/proxy/slice topology files | `test_proxy_large_read.py`, `test_tpc_tls.py`, `test_tpc_delegation.py`, `test_tpc_gsi_nginx_source.py`, `test_tpc_gsi_outbound.py`, `test_tpc_async_open.py`, `test_slice_cache.py`: register multi-node dependency graph; replace free ports with endpoint interpolation. | Topologies start before tests; no per-test process startup. |
| CMS/CNS/mesh files | `test_cns.py`, `test_cms_fast_settle.py`, `test_cms_resilience.py`, `test_cms_state_have_select.py`, `test_cms_wire_pup_conformance.py`, `cms_mesh_lib.py`: express manager/data-node graphs as specs; replace shell-managed mesh boot with Python topology object. | Mesh/CMS tests report startup failures at session start. |
| Conformance/interop files | `test_conformance_topologies.py`, `test_xrootd_conformance.py`, `official_interop_lib.py`, `wlcg_conformance_fleet.py`, `test_gohep_interop.py`: move fleet construction into registry factories; manifest publishes all endpoints. | Interop suites attach to registry endpoints only. |
| Evil/security files | `test_evil_actor.py`, `test_evil_actor_v2.py`, `_test_evil_actor_v3_helpers.py`, `test_chaos_mixed_auth.py`, `test_integrity_matrix.py`, `_test_gsi_handshake_helpers.py`, `_test_proxy_protocol_edges_helpers.py`, `test_root_open_existence_oracle.py`: registry owns targets; malicious clients remain in tests with hard timeouts. | Security tests cannot orphan nginx. |
| Multi-user files | `test_mu_stage_modes.py`, `test_mu_cache_serve_authz.py`, `test_mu_sidecar_config_guard.py`, `test_mu_sidecar_hidden.py`, `test_mu_webdav_authz.py`, `mu_authz_lib/fleet.py`: port fleet creation to registry plus Python account/credential setup. | Multi-user fleet starts once and is manifest-visible. |
| I/O feature files | `test_access_log_batch.py`, `test_checksum_on_write.py`, `test_crc64.py`, `test_pmark.py`, `test_put_content_encoding.py`, `test_readv_segment_size.py`, `test_readv_variable_blocks.py`, `test_srr_endpoint.py`, `test_ssi.py`, `test_ssi_config.py`, `test_ssi_metrics.py`, `test_ssi_wire.py`, `test_shutdown_resume.py`, `test_mirror_upstream.py`, `test_metadata_stress.py`, `test_dropin_byte_for_byte.py`, `test_native_xrdcp_xrdfs_b.py`, `test_libbrix.py`, `test_phase51_resilience.py`, `_cache_partial_helpers.py`: register feature specs and use registry metadata for logs/data. | No direct nginx lifecycle remains; feature assertions unchanged. |

### Shell Deletion Ledger

For each listed shell file, create the Python target, port the behavior, run parity, then delete the shell file. The target naming rule is mandatory unless a more specific target is listed below.

| Shell file pattern | Python target | Required changes |
|---|---|---|
| `tests/run_<name>.sh` | `tests/cmdscripts/<name>.py` + `tests/test_cmd_<name>.py` | Port commands to `run_cmd`, register servers, delete shell. |
| `tests/cvmfs/run_<name>.sh` | `tests/cmdscripts/cvmfs_<name>.py` + `tests/test_cvmfs_<name>.py` | Port CVMFS flow to pytest, use Python mount/cleanup helpers, delete shell. |
| `tests/c/run_<name>.sh` | `tests/cmdscripts/c_<name>.py` + `tests/test_c_<name>.py` | Compile/run C helper via Python subprocess, delete shell. |
| `tests/ceph/run_<name>.sh` | `tests/cmdscripts/ceph_<name>.py` + `tests/test_ceph_<name>.py` | Port Ceph setup/probes to Python, skip when Ceph unavailable, delete shell. |
| `tests/unit/run_tests.sh` | `tests/cmdscripts/unit_tests.py` + `tests/test_cmd_unit_tests.py` | Run unit binaries from Python, delete shell. |
| `tests/fuzz/run_all.sh` | `tests/cmdscripts/fuzz_all.py` + `tests/test_cmd_fuzz_all.py` | Run fuzz smoke/corpus checks from Python, delete shell. |
| `tests/profile_*.sh` | `tests/cmdscripts/profile_<name>.py` + opt-in pytest marker | Port profiling commands to Python, mark non-default if expensive, delete shell. |
| `tests/lint_*.sh` | `tests/test_lint_<name>.py` | Reimplement lint in Python, delete shell. |
| `tests/build_*.sh` | `tests/test_build_<name>.py` or `tests/cmdscripts/build_<name>.py` | Run build commands through Python, delete shell. |
| `tests/brutal_teardown.sh` | `tests/cmdscripts/brutal_teardown.py` | Python cleanup utility; delete shell. |
| `tests/manage_test_servers.sh` | `tests/cmdscripts/manage_test_servers.py` | Python registry/fleet manager; delete shell. |
| Remaining live scenario shells | Dedicated Python command module per script or coherent shared implementation | Port the shell's process/config/client flow directly; no dispatchers, pytest selectors, or shell invocation. |
| `tests/ceph_harness.sh` | Dedicated Ceph harness Python command module | Port the container/process flow directly; delete shell after parity/backfill. |
| `tests/frm_fake_mss.sh` | `tests/cmdscripts/frm_fake_mss.py` | Port fake MSS behavior to Python executable/helper, delete shell. |
| `tests/fwd_b_token_forward_probe.sh` | Dedicated forwarding-probe Python command module | Port the probe directly; delete shell after parity/backfill. |

## Implementation Waves

## Exact Edit Pattern For Every File Type

Use this section as the literal checklist when touching each file in the inventories above.

### Every Python Test File Listed Above

For each `tests/test_*.py`, `tests/_*_helpers.py`, `tests/*_lib.py`, and `tests/*_fleet.py` file named in this document:

- [ ] Add imports:
  - [ ] `from server_registry import NginxInstanceSpec, register_nginx`
  - [ ] `from server_registry import server as registry_server_lookup` only when module-level lookup is needed.
- [ ] Add one module-level spec per server:
  - [ ] `SPEC_<ROLE> = NginxInstanceSpec(...)`
  - [ ] `register_nginx(SPEC_<ROLE>)`
- [ ] Use spec naming convention:
  - [ ] `test_<module_stem>_<role>` for test-private servers.
  - [ ] `fleet_<domain>_<role>` for shared fleet servers.
  - [ ] `cmd_<script_stem>_<role>` for former shell-script servers.
- [ ] Use template naming convention:
  - [ ] `tests/configs/nginx_<module_stem>_<role>.conf` for private nginx templates.
  - [ ] `tests/configs/xrootd_<module_stem>_<role>.conf` for reference xrootd templates.
  - [ ] `tests/configs/cmd_<script_stem>_<role>.conf` for former shell-script templates.
- [ ] Delete functions named or shaped like:
  - [ ] `_start_nginx`
  - [ ] `_spawn_nginx`
  - [ ] `_write_conf`
  - [ ] `_render_config` when it only wraps a template.
  - [ ] `_stop_nginx`
  - [ ] local `Instance.start/stop/reload` unless replaced by lifecycle harness methods.
- [ ] Replace fixtures that return dicts like `{host, port, url, data}` with:
  - [ ] `srv = registry_server("spec_name")`
  - [ ] `return srv`
- [ ] Replace direct client invocations:
  - [ ] `subprocess.run([...])` -> `command_runner([...])` when invoking external clients.
  - [ ] Keep Python-internal pure computations as normal function calls.
- [ ] Add timeouts to every external command.
- [ ] Move all generated data into:
  - [ ] `tmp_path` for per-test scratch.
  - [ ] `srv.data_root` for server-visible files.
  - [ ] `srv.prefix` for server-private runtime state.
- [ ] Replace log path literals with:
  - [ ] `srv.error_log`
  - [ ] `srv.access_log`
  - [ ] `srv.logs_dir`
- [ ] Add standalone verification:
  - [ ] `python -m py_compile <file>`
  - [ ] `PYTHONPATH=tests pytest <file> -q -p no:xdist`

### Every Shell File Listed Above

For each `.sh` file named in this document:

- [ ] Create Python command module:
  - [ ] `tests/cmdscripts/<derived_name>.py`
- [ ] Create pytest collector:
  - [ ] `tests/test_cmd_<derived_name>.py`, or the domain-specific target listed in the shell deletion ledger.
- [ ] Move top-level shell variables to Python constants:
  - [ ] `NGINX=...` -> use `settings.NGINX_BIN` or registry launcher.
  - [ ] `PFX=...` -> `tmp_path` or registry `prefix`.
  - [ ] `PORT=...` -> registry dynamic port or named settings port.
  - [ ] `DATA=...` -> registry `data_root`.
- [ ] Replace shell functions:
  - [ ] `cleanup()` -> pytest fixture finalizer or registry teardown.
  - [ ] `ok()/bad()` -> Python assertions with message.
  - [ ] `wait_*()` -> launcher readiness helpers.
  - [ ] `mkconf()` -> committed template plus registry spec.
- [ ] Replace shell commands:
  - [ ] `cat > nginx.conf <<EOF` -> `tests/configs/*.conf`.
  - [ ] `"$NGINX" -c ...` -> registry `start_nginx`.
  - [ ] `"$NGINX" -s stop` -> registry teardown.
  - [ ] `curl ...` -> `run_cmd(["curl", ...])`.
  - [ ] `xrdcp ...` -> `run_cmd([settings.XRDCP_BIN, ...])`.
  - [ ] `xrdfs ...` -> `run_cmd([settings.XRDFS_BIN, ...])`.
  - [ ] `openssl ...` -> `run_cmd(["openssl", ...])`.
  - [ ] `grep/sed/awk` assertions -> Python string/regex/pathlib checks.
- [ ] Preserve every externally visible assertion:
  - [ ] exit code checks
  - [ ] stdout/stderr substring checks
  - [ ] output file existence checks
  - [ ] checksum/size/content checks
  - [ ] HTTP status/header/body checks
  - [ ] xrootd stat/read/write/list checks
- [ ] Add skip behavior:
  - [ ] missing binary -> `pytest.skip`
  - [ ] missing kernel feature -> `pytest.skip`
  - [ ] missing service dependency -> `pytest.skip`
  - [ ] permission/root requirement -> `pytest.skip`
- [ ] Delete original shell file.
- [ ] Verify:
  - [ ] `python -m py_compile tests/cmdscripts/<derived_name>.py`
  - [ ] `PYTHONPATH=tests pytest tests/test_cmd_<derived_name>.py -q`
  - [ ] `rg --files tests -g '*.sh'` eventually returns no files.

### Every Config-Generating File

For every Python or shell source that currently creates an nginx/xrootd config:

- [ ] Create or reuse a template in `tests/configs/`.
- [ ] Template placeholders must be uppercase:
  - [ ] `{PREFIX}`
  - [ ] `{DATA_ROOT}`
  - [ ] `{LOG_DIR}`
  - [ ] `{PORT}`
  - [ ] `{HTTP_PORT}`
  - [ ] `{UPSTREAM_PORT}`
  - [ ] `{CERT}`
  - [ ] `{KEY}`
  - [ ] `{CA_DIR}`
- [ ] Do not mention multiline placeholder names inside comments.
- [ ] Render through strict registry rendering.
- [ ] Add `nginx -t`/xrootd config validation in launcher startup.
- [ ] Delete inline config construction after parity.

### Every File That Starts More Than One Server

- [ ] Create one `NginxInstanceSpec`/`XrootdInstanceSpec` per process.
- [ ] Model ordering with `requires=[...]`.
- [ ] Put all endpoint wiring in `template_values` or endpoint interpolation.
- [ ] Create a topology fixture returning named endpoints:
  - [ ] `topology.origin`
  - [ ] `topology.proxy`
  - [ ] `topology.destination`
  - [ ] `topology.redirector`
  - [ ] `topology.metrics`
- [ ] Make startup atomic:
  - [ ] if any node fails, stop all nodes in that topology.
  - [ ] include all relevant logs in failure output.

### Every File That Tests Restart/Crash/Reload

- [ ] Use lifecycle harness methods only.
- [ ] Keep the test assertion about lifecycle behavior.
- [ ] Do not spawn unmanaged nginx.
- [ ] Do not use shell signals directly.
- [ ] Use `registry.process_snapshot` before and after lifecycle action.
- [ ] Assert old/new worker pid behavior explicitly where relevant.

### Every File That Compiles Or Runs C Helpers

- [ ] Move shell compile command to Python `run_cmd`.
- [ ] Use `tmp_path` for output binaries unless the existing Makefile target is required.
- [ ] Capture compiler stdout/stderr.
- [ ] Skip when compiler or dependency headers are missing.
- [ ] Assert helper exit code and output.
- [x] Delete shell runner. (2026-07-16)

### Wave 1: Skeleton And Guardrails

- [ ] Add registry and launcher.
- [ ] Add marker and conftest integration.
- [ ] Add manifest support.
- [ ] Add smoke test.
- [ ] Add lint in warn-only mode.
- [x] Convert `tests/run_af_family_conf.sh` as first Python-managed command proof.
- [ ] Convert one single-server Python fixture.

Effort: 2-3 days.

### Wave 2: Low-Risk Python Fixtures

- [ ] Convert client/xrdiag single-server fixtures.
- [ ] Convert dashboard/guard/storage-panel fixtures.
- [ ] Convert S3/token/macaroons single-server fixtures.
- [ ] Turn lint to fail for new Python direct starts.

Effort: 2-3 days.

### Wave 3: Shell Deletion Via Python Command Tests

- [ ] Add `tests/cmdscripts/` patterns.
- [ ] Convert first 20 `run_*.sh` scripts.
- [ ] Add pytest-owned command-line flows.
- [ ] Delete converted `.sh` files.
- [ ] Turn shell heredoc/direct-run lint to fail for all test paths.

Effort: 1 week.

### Wave 4: Multi-Server Topologies

- [ ] Convert proxy/TPC/slice/CNS/GoHEP groups.
- [ ] Add dependency-order tests.
- [ ] Add topology startup diagnostics.

Effort: 1 week.

### Wave 5: Long Tail And Shell Removal

- [ ] Convert CVMFS, Ceph, C helper, userns, and privileged scripts to Python/pytest.
- [ ] Delete every remaining shell file under `tests/`.
- [ ] Remove dead shell lifecycle helpers after Python parity.
- [ ] Update `TESTING.md` and `README.md`.

Effort: 1-2 weeks.

## Estimated Total Work

- [ ] Minimum useful Python registry: 2-3 days.
- [ ] Python-test migration with guardrails: 4-6 days.
- [ ] Meaningful Python replacement first pass: 1-2 weeks.
- [ ] Full cleanup with zero shell scripts remaining: 2-4 weeks.

Expected first-wave payoff:

- [ ] 20-35 fewer ad hoc Python nginx fixtures.
- [ ] 25-45 shell scripts deleted in the first migration wave.
- [ ] 400-800 Python test LoC removed.
- [ ] 800-2000 shell LoC removed in the first migration wave.
- [ ] Earlier startup failures and fewer mid-suite port collisions.
- [ ] One lifecycle model for Python and command-line-tool tests.

## Hard Requirements

- [ ] All tests are managed and run by Python/pytest.
- [ ] No shell scripts remain under `tests/` at completion.
- [ ] Lifecycle behavior is tested through Python lifecycle harness primitives.
- [ ] Config variants are not hidden in Python strings.
- [ ] Real command-line tools continue to be tested through Python `subprocess`.
- [ ] Operator entry points are Python modules, pytest targets, or documented Python commands.
- [ ] Fixed ports are optional; registry-owned dynamic ports are preferred where practical.
