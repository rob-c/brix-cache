# Phase 81: Test Server Registry

## Goal

Move every test to Python/pytest and remove shell scripts from the test tree. Tests should register the nginx/xrootd topology they need before execution, then pytest session setup should render configs, start every required server, publish endpoint metadata, and own teardown.

Command-line coverage stays: Python-managed tests may still call `xrdcp`, `xrdfs`, `curl`, `brixmount`, C helpers, and other real tools. What moves out of individual tests is server lifecycle.

## Done Means

- [ ] Test configs stay reviewable under `tests/configs/`.
- [ ] Python tests do not hand-roll nginx start/stop outside the registry/lifecycle harness.
- [ ] Shell tests are migrated to Python/pytest.
- [ ] No `.sh` file remains in `tests/`, including wrappers.
- [ ] Registered servers start before the first test body executes.
- [ ] xdist workers consume a shared `$TEST_ROOT/registry/manifest.json`.
- [ ] Attach mode, remote mode, and `TEST_SKIP_SERVER_SETUP=1` remain safe.
- [ ] Command-line tests still execute real command-line clients from Python.
- [ ] Former operator entry points are Python modules or pytest targets, not shell wrappers.

## New Files

- [ ] `tests/server_registry.py` - registration API, spec model, manifest read/write.
- [ ] `tests/server_launcher.py` - render, `nginx -t`, start, readiness, stop.
- [ ] `tests/cmdscripts/__init__.py` - package for Python replacements of former `run_*.sh` scripts.
- [ ] `tests/test_server_registry_smoke.py` - minimal registry-backed smoke test.
- [ ] `tests/test_server_registry_lint.py` - blocks new unregistered nginx launches and shell heredoc configs.
  - [ ] Fails if any `.sh` file exists under `tests/` after the migration is complete.
- [ ] `tests/configs/nginx_registry_smoke.conf` - tiny starter template if no existing template fits cleanly.
- [ ] `tests/configs/REGISTRY_MIGRATION.md` - operator notes and mandatory migration policy.

## Existing Harness Files To Edit

- [ ] `tests/conftest.py`
  - [ ] Register marker `uses_lifecycle_harness`.
  - [ ] Start registry servers after shared data/PKI setup.
  - [ ] Skip registry startup in remote/attach/skip modes.
  - [ ] In xdist controller, write manifest.
  - [ ] In xdist workers, read manifest and never start servers.
  - [ ] Stop registry-owned servers during session teardown.

- [ ] `tests/settings.py`
  - [ ] Add registry paths: `REGISTRY_ROOT`, `REGISTRY_MANIFEST`.
  - [ ] Add env overrides for registry behavior.
  - [ ] Add helpers for stable per-session port allocation.

- [ ] `tests/config_templates.py`
  - [ ] Keep existing literal template rendering.
  - [ ] Add unresolved-placeholder detection.
  - [ ] Add optional strict mode for registry launches.

- [ ] `tests/manage_test_servers.sh`
  - [ ] Replace authoritative test lifecycle behavior with Python registry calls.
  - [ ] Replace the shell entry point with Python command/module documentation.
  - [ ] Remove direct nginx/xrootd start logic from the test runner path.

- [ ] `tests/lib/dedicated.sh`
  - [ ] Port behavior to `tests/lib_py/dedicated.py`.
  - [ ] Remove from authoritative test execution.

- [ ] `tests/lib/nginx.sh`
  - [ ] Port behavior to `tests/lib_py/nginx.py`.
  - [ ] Remove shell start/stop behavior from authoritative test execution.

- [ ] `tests/lib/util.sh`
  - [ ] Port needed helpers to Python.
  - [ ] Remove shell config rendering from authoritative test execution.

- [ ] `TESTING.md`
  - [ ] Document registry mode, attach mode, and migration policy.

- [ ] `README.md`
  - [ ] Add short note pointing developers to registry docs for new tests.

## Registry API Checklist

- [ ] Define `NginxInstanceSpec`.
- [ ] Fields:
  - [ ] `name`
  - [ ] `template`
  - [ ] `port`
  - [ ] `protocol`
  - [ ] `data_root`
  - [ ] `extra_ports`
  - [ ] `env`
  - [ ] `template_values`
  - [ ] `readiness`
  - [ ] `requires`
  - [ ] `tags`
  - [ ] `allow_remote_skip`
  - [ ] `reason`
- [ ] Implement `register_nginx(spec)`.
- [ ] Implement `get_server(name)`.
- [ ] Implement dependency ordering.
- [ ] Implement free-port reservation before render.
- [ ] Implement endpoint interpolation between specs.
- [ ] Implement manifest serialization.
- [ ] Implement manifest validation for workers.
- [ ] Implement readable startup failure reports.
- [ ] Implement pidfile and process-group cleanup.
- [ ] Implement final leak check for registry-owned nginx processes.

## Special Lifecycle Coverage

No test is exempt from Python/pytest ownership. Tests whose subject is lifecycle behavior must use Python harness primitives rather than unmanaged shell or ad hoc per-test server launch code.

Required lifecycle harness primitives:

- [ ] `registry.start(spec)` for controlled startup.
- [ ] `registry.stop(name)` for controlled shutdown.
- [ ] `registry.reload(name)` for `nginx -s reload` coverage.
- [ ] `registry.reopen(name)` for `nginx -s reopen` coverage.
- [ ] `registry.expect_config_failure(spec)` for invalid config tests.
- [ ] `registry.kill_worker(name, signal)` for worker crash/fork-safety tests.
- [ ] `registry.restart(name)` for restart durability tests.
- [ ] `registry.process_snapshot(name)` for master/worker accounting tests.
- [ ] `registry.run_privileged_step(...)` for userns/mount/privileged setup, skipped cleanly when unavailable.
- [ ] `registry.run_cmd(...)` wrapper around `subprocess.run` for command-line clients.

Files requiring lifecycle-harness migration:

- [ ] `tests/test_reload.py`
- [ ] `tests/test_lifecycle_speed.py`
- [ ] `tests/test_shm_fork_safety.py`
- [ ] `tests/test_phase22_health_check.py`
- [ ] `tests/test_phase21_proxy_filter.py`
- [ ] `tests/test_phase23_admin_api.py`
- [ ] `tests/test_phase24_mirror.py`
- [ ] `tests/test_phase25_ratelimit.py`
- [ ] `tests/userns/e2e_redteam.py`
- [ ] `tests/userns/run.sh`
- [ ] `tests/valgrind/run_valgrind.sh`
- [ ] `tests/build_dynamic_modules.sh`
- [ ] `tests/build_sanitizer.sh`
- [ ] `tests/brutal_teardown.sh`
- [ ] `tests/run_suite.sh`
- [ ] `tests/manage_test_servers.sh`

## Python Migration Targets

### Single-Server, Low Risk

- [ ] `tests/test_client_xrd_frontend.py`
- [ ] `tests/test_client_xrd_doctor_login.py`
- [ ] `tests/test_xrd_busybox.py`
- [ ] `tests/test_client_xrdrc_alias.py`
- [ ] `tests/test_xrddiag_capture.py`
- [ ] `tests/test_xrddiag_watch.py`
- [ ] `tests/test_xrddiag_probe.py`
- [ ] `tests/test_client_xrdfs_tools.py`
- [ ] `tests/test_client_xrdcp_bulk.py`
- [ ] `tests/test_xrdmapc.py`
- [ ] `tests/test_native_client_diagnostics.py`
- [ ] `tests/test_client_web_transfer.py`
- [ ] `tests/test_dashboard_config_anon.py`
- [ ] `tests/test_dashboard_files.py`
- [ ] `tests/test_storage_backend_panel.py`
- [ ] `tests/test_scan.py`
- [ ] `tests/test_arc_guard.py`
- [ ] `tests/test_guard_endpoints.py`
- [ ] `tests/test_xrdhttp_guard.py`
- [ ] `tests/test_stream_guard.py`
- [ ] `tests/test_netfault_stream.py`
- [ ] `tests/test_phase27_memsafety.py`
- [ ] `tests/test_cache_reap_metrics.py`
- [ ] `tests/test_webdav_lock_startup_sweep.py`

### Auth, Token, S3, WebDAV

- [ ] `tests/test_token_aud_array.py`
- [ ] `tests/test_token_es256.py`
- [ ] `tests/test_macaroon_request.py`
- [ ] `tests/test_macaroon_negative.py`
- [ ] `tests/test_s3_list_cache.py`
- [ ] `tests/test_s3_auth_oracle.py`
- [ ] `tests/test_dig.py`
- [ ] `tests/test_host_auth.py`
- [ ] `tests/test_pwd_auth.py`
- [ ] `tests/test_native_sss.py`
- [ ] `tests/test_native_krb5.py`
- [ ] `tests/test_native_gsi_interop.py`
- [ ] `tests/test_acc.py`
- [ ] `tests/test_acc_residual.py`

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
- [ ] `tests/test_xfer_resume_sweep.py`
- [ ] `tests/test_xfer_wt_replay.py`
- [ ] `tests/test_xfer_wt_journal.py`

### Multi-Server Topologies

- [ ] `tests/test_proxy_large_read.py`
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
- [ ] `tests/test_cache_reap_metrics.py`
- [ ] `tests/test_checksum_on_write.py`
- [ ] `tests/test_crc64.py`
- [ ] `tests/test_pmark.py`
- [ ] `tests/test_put_content_encoding.py`
- [ ] `tests/test_readv_segment_size.py`
- [ ] `tests/test_readv_variable_blocks.py`
- [ ] `tests/test_srr_endpoint.py`
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

- [ ] `tests/run_af_family_conf.sh`
- [ ] `tests/run_cache_pblock_pblock.sh`
- [ ] `tests/run_credential_http_bearer.sh`
- [ ] `tests/run_credential_webdav_xroot.sh`
- [ ] `tests/run_credential_xroot_gsi.sh`
- [ ] `tests/run_dashboard_vfs_browse.sh`
- [ ] `tests/run_tpc_fwd_root.sh`
- [ ] `tests/run_tpc_fwd_webdav.sh`
- [ ] `tests/run_storage_backend_metrics.sh`
- [ ] `tests/run_storage_backend_schemes.sh`
- [ ] `tests/run_s3_storage_backend.sh`
- [ ] `tests/run_s3_store_writable.sh`
- [ ] `tests/run_s3_usermeta.sh`
- [ ] `tests/run_s3_tape_residency.sh`
- [ ] `tests/run_cache_http_source.sh`
- [ ] `tests/run_cache_xroot_origin.sh`
- [ ] `tests/run_cache_xroot_webdav_offload.sh`
- [ ] `tests/run_cache_s3_origin.sh`
- [ ] `tests/run_cache_backend_source.sh`
- [ ] `tests/run_cache_pblock_posix.sh`
- [ ] `tests/run_cache_wt_driver.sh`
- [ ] `tests/run_cache_watermark.sh`
- [ ] `tests/run_cache_watermark_config.sh`
- [ ] `tests/run_cache_reaper.sh`
- [ ] `tests/run_cache_stage_throttle.sh`
- [ ] `tests/run_cache_slice_gsi_legacy.sh`
- [ ] `tests/run_cache_unit.sh`

### Credential, Delegation, Auth, Proxy

- [ ] `tests/run_credential_xroot_ztn.sh`
- [ ] `tests/run_credential_xroot_gsi_writeback.sh`
- [ ] `tests/run_credential_wt_ztn.sh`
- [ ] `tests/run_credential_dup_warn.sh`
- [ ] `tests/run_delegation_twostep.sh`
- [ ] `tests/run_delegation_upload.sh`
- [ ] `tests/run_tpc_delegation_nginx.sh`
- [ ] `tests/run_csi_trust.sh`
- [ ] `tests/run_gsi_store_memo.sh`
- [ ] `tests/run_gsi_intermediate_ca.sh`
- [ ] `tests/run_ktls.sh`
- [ ] `tests/run_tap_proxy.sh`
- [ ] `tests/run_tap_proxy_gsi.sh`
- [ ] `tests/run_tap_proxy_gsi_hybrid.sh`
- [ ] `tests/run_proxy_env_unit.sh`
- [ ] `tests/run_proxy_env_live.sh`
- [ ] `tests/run_proxy_metadata_phase.sh`
- [ ] `tests/run_fwd_brix_brix.sh`
- [ ] `tests/run_fwd_brix_xrootd.sh`
- [ ] `tests/run_fwd_xrootd_brix.sh`
- [ ] `tests/run_user_backend_cred.sh`
- [ ] `tests/run_user_backend_cred_root.sh`
- [ ] `tests/run_user_backend_cred_ns.sh`
- [ ] `tests/run_user_backend_cred_p2.sh`
- [ ] `tests/run_multiuser_authz.sh`
- [ ] `tests/run_cred_metrics.sh`
- [ ] `tests/fwd_b_token_forward_probe.sh`

### CVMFS And Brixmount

- [ ] `tests/run_cvmfs_catalog_unit.sh`
- [ ] `tests/run_cvmfs_classify.sh`
- [ ] `tests/run_cvmfs_verify.sh`
- [ ] `tests/run_cvmfs_bench.sh`
- [ ] `tests/run_cvmfs_reverse.sh`
- [ ] `tests/run_cvmfs_holdopen.sh`
- [ ] `tests/run_cvmfs_proxy.sh`
- [ ] `tests/run_cvmfs_manifest.sh`
- [ ] `tests/run_cvmfs_minimal.sh`
- [ ] `tests/run_cvmfs_resilience.sh`
- [ ] `tests/run_cvmfs_conn_reuse.sh`
- [ ] `tests/run_cvmfs_stock.sh`
- [ ] `tests/run_cvmfs_unified_origin.sh`
- [ ] `tests/run_cvmfs_upstream_metrics.sh`
- [ ] `tests/run_cvmfs_conf_unit.sh`
- [ ] `tests/run_cvmfs_core_unit.sh`
- [ ] `tests/run_cvmfs_client_unit.sh`
- [ ] `tests/run_cvmfs_fetch_unit.sh`
- [ ] `tests/run_cvmfs_logging.sh`
- [ ] `tests/run_cvmfs_select.sh`
- [ ] `tests/run_cvmfs_selectlog.sh`
- [ ] `tests/run_cvmfs_keepalive.sh`
- [ ] `tests/run_cvmfs_failover.sh`
- [ ] `tests/run_cvmfs_shared_cache.sh`
- [ ] `tests/run_cvmfs_evict.sh`
- [ ] `tests/run_cvmfs_brix_all.sh`
- [ ] `tests/run_cvmfs_faultproxy_bench.sh`
- [ ] `tests/run_mount_cvmfs_live.sh`
- [ ] `tests/run_brixmount_unit.sh`
- [ ] `tests/run_brixmount_live.sh`
- [ ] `tests/run_brixcvmfs_build.sh`
- [ ] `tests/run_brixcvmfs_check.sh`
- [ ] `tests/run_brixcvmfs_live.sh`
- [ ] `tests/run_brixcvmfs_atlas_live.sh`
- [ ] `tests/run_brixcvmfs_clever_live.sh`
- [ ] `tests/run_brixcvmfs_overlay.sh`
- [ ] `tests/cvmfs/run_matrix.sh`
- [ ] `tests/cvmfs/run_baselines.sh`
- [ ] `tests/cvmfs/spike_cas_hash.sh`
- [ ] `tests/cvmfs/netem_lab.sh`

### Tier, Remote Backend, Stage, Tape, PBlock

- [ ] `tests/run_tier_matrix_drivers.sh`
- [ ] `tests/run_tier_remote_stage.sh`
- [ ] `tests/run_tier_remote_evict.sh`
- [ ] `tests/run_tier_remote_store.sh`
- [ ] `tests/run_tier_sidecar_meta.sh`
- [ ] `tests/run_tier_slice_fill.sh`
- [ ] `tests/run_tier_instance_lifetime.sh`
- [ ] `tests/run_remote_backend_serve_offload.sh`
- [ ] `tests/run_remote_backend_meta.sh`
- [ ] `tests/run_remote_backend_write.sh`
- [ ] `tests/run_remote_backend_staging.sh`
- [ ] `tests/run_remote_backend_webdav.sh`
- [ ] `tests/run_stage_reconcile.sh`
- [ ] `tests/run_stage_async_remote_flush.sh`
- [ ] `tests/run_root_stage_writeback.sh`
- [ ] `tests/run_root_slice_fill.sh`
- [ ] `tests/run_tape_recall_stream.sh`
- [ ] `tests/run_tape_recall_async.sh`
- [ ] `tests/run_tape_exec_adapter.sh`
- [ ] `tests/run_pblock_meta_gsi.sh`
- [ ] `tests/run_pblock_writethrough.sh`
- [ ] `tests/run_pblock_root.sh`
- [ ] `tests/run_pblock_webdav.sh`

### X509, Token, Client, Load, Misc

- [ ] `tests/run_token_conformance.sh`
- [ ] `tests/run_token_differential.sh`
- [ ] `tests/run_x509_differential.sh`
- [ ] `tests/run_x509_matrix_differential.sh`
- [ ] `tests/run_official_xrootd_tests.sh`
- [ ] `tests/run_cross_compatible_tests.sh`
- [ ] `tests/run_client_features.sh`
- [ ] `tests/run_http_store_writable.sh`
- [ ] `tests/run_unified_conf.sh`
- [ ] `tests/run_overlay_unit.sh`
- [ ] `tests/run_ucred_conf.sh`
- [ ] `tests/run_io_uring_backend.sh`
- [ ] `tests/run_load_test.sh`
- [ ] `tests/run_xroot_cachestore_serve.sh`
- [ ] `tests/run_cachestore_sidecar.sh`
- [ ] `tests/run_xmeta.sh`
- [ ] `tests/run_nonstaged_reap.sh`
- [ ] `tests/run_scvmfs.sh`
- [ ] `tests/run_transparent_relay.sh`
- [ ] `tests/run_xfer_audit_sink.sh`
- [ ] `tests/run_cache_af_family.sh`
- [ ] `tests/run_sd_s3_meta.sh`
- [ ] `tests/demo_dashboard_live.sh`
- [ ] `tests/profile_lifecycle.sh`
- [ ] `tests/profile_load.sh`
- [ ] `tests/ceph_harness.sh`
- [ ] `tests/frm_fake_mss.sh`

### Static, Lint, Build, And Suite Entrypoints

- [ ] `tests/lint_alloc.sh`
- [ ] `tests/lint_loc.sh`
- [ ] `tests/build_dynamic_modules.sh`
- [ ] `tests/build_sanitizer.sh`
- [ ] `tests/run_suite.sh`
- [ ] `tests/brutal_teardown.sh`
- [ ] `tests/manage_test_servers.sh`

### C, Unit, Fuzz, Ceph Shells

- [ ] `tests/c/run_vfs_caps_tests.sh`
- [ ] `tests/c/run_sesslog_tests.sh`
- [ ] `tests/c/run_cache_lock_reclaim_tests.sh`
- [ ] `tests/c/run_flush_deadletter.sh`
- [ ] `tests/c/run_shm_mutex_recovery_tests.sh`
- [ ] `tests/c/run_ratelimit_gauge_reset_tests.sh`
- [ ] `tests/c/run_delegation_store.sh`
- [ ] `tests/c/run_fs_usage_tests.sh`
- [ ] `tests/c/run_slice_tests.sh`
- [ ] `tests/c/run_pblock_tests.sh`
- [ ] `tests/c/run_site_n2n_tests.sh`
- [ ] `tests/c/run_mu_unit.sh`
- [ ] `tests/c/run_x509_conformance_tests.sh`
- [ ] `tests/c/run_signing_policy_tests.sh`
- [ ] `tests/c/test_xrdcinfo.sh`
- [ ] `tests/c/run_cred_mint.sh`
- [ ] `tests/c/run_ucred_tests.sh`
- [ ] `tests/c/run_stage_reconcile_tests.sh`
- [ ] `tests/c/run_sd_ceph_compat_tests.sh`
- [ ] `tests/c/run_meta_advisory_tests.sh`
- [ ] `tests/c/run_compression_tests.sh`
- [ ] `tests/c/run_cache_admit_tests.sh`
- [ ] `tests/c/run_stage_admit_tests.sh`
- [ ] `tests/c/run_cache_storage_tests.sh`
- [ ] `tests/c/run_vo_token_tests.sh`
- [ ] `tests/c/run_cinfo_tests.sh`
- [ ] `tests/c/run_x509_oracle.sh`
- [ ] `tests/c/run_sreq_compat.sh`
- [ ] `tests/c/run_sd_remote_wrongkind_tests.sh`
- [ ] `tests/unit/run_tests.sh`
- [ ] `tests/fuzz/run_all.sh`
- [ ] `tests/ceph/build_in_container.sh`
- [ ] `tests/ceph/run_striper_migrate.sh`
- [ ] `tests/ceph/run_rescue_tools.sh`
- [ ] `tests/ceph/run_cephfs_ro_live.sh`
- [ ] `tests/ceph/ceph_export_smoke.sh`
- [ ] `tests/ceph/run_py_migrate.sh`
- [ ] `tests/ceph/run_sd_ceph_cred_live.sh`
- [ ] `tests/ceph/cephfs_ro_smoke.sh`
- [ ] `tests/ceph/run_sd_ceph_live.sh`

### Shell Libraries To Port And Delete

- [ ] `tests/lib/tpc_fwd.sh`
- [ ] `tests/lib/xrdhttp.sh`
- [ ] `tests/lib/dedicated.sh`
- [ ] `tests/lib/fwd_matrix.sh`
- [ ] `tests/lib/util.sh`
- [ ] `tests/lib/pki.sh`
- [ ] `tests/lib/nginx.sh`
- [ ] `tests/lib/refxrootd.sh`
- [ ] `tests/guard/run_guard_core.sh`

Replacement modules:

- [ ] `tests/lib_py/tpc_fwd.py`
- [ ] `tests/lib_py/xrdhttp.py`
- [ ] `tests/lib_py/dedicated.py`
- [ ] `tests/lib_py/fwd_matrix.py`
- [ ] `tests/lib_py/pki.py`
- [ ] `tests/lib_py/nginx.py`
- [ ] `tests/lib_py/refxrootd.py`
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

- [ ] `tests/server_registry.py`
  - [ ] Add `@dataclass(frozen=True) NginxInstanceSpec`.
  - [ ] Add `@dataclass(frozen=True) CommandSpec` for former shell command flows.
  - [ ] Add process-independent global registry populated at module import time.
  - [ ] Add duplicate-name detection with file/line diagnostics.
  - [ ] Add `register_nginx`, `register_xrootd`, `register_command_suite`.
  - [ ] Add `server(name)` lookup for tests.
  - [ ] Add `manifest_write(path)` and `manifest_read(path)`.
  - [ ] Add `selected_specs(pytest_items)` so only collected tests start their needed servers.

- [ ] `tests/server_launcher.py`
  - [ ] Add `render_nginx(spec)`.
  - [ ] Add `nginx_test(spec)` with captured stdout/stderr.
  - [ ] Add `start_nginx(spec)` and `stop_nginx(instance)`.
  - [ ] Add lifecycle calls: reload, reopen, restart, kill worker, process snapshot.
  - [ ] Add readiness probes for root, WebDAV, S3, metrics, CMS, and raw TCP.
  - [ ] Add `run_cmd(argv, *, env=None, timeout=..., input=None)` wrapper used by command tests.
  - [ ] Add structured failure object that includes config path, logs, command, rc, and output tail.

- [ ] `tests/cmdscripts/__init__.py`
  - [ ] Export shared helpers for former shell tests.
  - [ ] Export `main()` helper for optional direct `python -m tests.cmdscripts.<name>` debugging.
  - [ ] Keep all logic importable by pytest; no shell wrapper required.

- [ ] `tests/test_server_registry_smoke.py`
  - [ ] Register a one-port nginx from a committed config template.
  - [ ] Assert registry starts it before test body.
  - [ ] Assert manifest lookup returns host, port, prefix, config, data root.
  - [ ] Assert xdist worker can read the manifest without starting a process.

- [ ] `tests/test_server_registry_lint.py`
  - [ ] Fail on `*.sh` anywhere under `tests/`.
  - [ ] Fail on unregistered `subprocess.Popen([NGINX...])`.
  - [ ] Fail on unregistered `subprocess.run([NGINX...])` start/stop/reload.
  - [ ] Fail on inline nginx heredocs or multiline strings containing `events {` plus `stream {`/`http {`.
  - [ ] Fail on new test code importing shell helpers.
  - [ ] Allow `subprocess.run` for command-line clients only through `registry.run_cmd` or command helpers.

- [ ] `tests/configs/nginx_registry_smoke.conf`
  - [ ] Add smallest possible config using placeholders for prefix, port, data root, logs.
  - [ ] Use no domain-specific module features beyond anonymous root read.

- [ ] `tests/configs/REGISTRY_MIGRATION.md`
  - [ ] Explain how to add a new registry-backed server.
  - [ ] Explain how to port a former shell script.
  - [ ] Document naming convention for `tests/cmdscripts/*.py`.
  - [ ] Document that `.sh` files are forbidden after this phase.

### Existing Harness Files

- [ ] `tests/conftest.py`
  - [ ] Import registry during pytest configuration.
  - [ ] Add `pytest_collection_modifyitems` pass that records specs needed by collected tests.
  - [ ] Start registry specs in controller `pytest_sessionstart` after `_setup_session` seeds data/PKI.
  - [ ] Write `$TEST_ROOT/registry/manifest.json`.
  - [ ] In xdist workers, read manifest and skip all starts.
  - [ ] Add `registry_server` fixture returning endpoint metadata.
  - [ ] Add `command_runner` fixture wrapping `registry.run_cmd`.
  - [ ] Ensure teardown stops registry instances before shared tree removal.

- [ ] `tests/settings.py`
  - [ ] Add `REGISTRY_ROOT = os.path.join(TEST_ROOT, "registry")`.
  - [ ] Add `REGISTRY_MANIFEST = os.path.join(REGISTRY_ROOT, "manifest.json")`.
  - [ ] Add `TEST_REGISTRY_START=0/1` override.
  - [ ] Add `TEST_REGISTRY_KEEP_LOGS=1` override.
  - [ ] Add `REGISTRY_PORT_BASE` only for tests that require stable port bands.
  - [ ] Keep dynamic ports default for newly migrated tests.

- [ ] `tests/config_templates.py`
  - [ ] Add strict placeholder validation.
  - [ ] Add `render_config_to_path(name, dest, **values)`.
  - [ ] Keep backward compatibility for already migrated tests during transition.
  - [ ] Make registry use strict mode by default.

- [ ] `TESTING.md`
  - [ ] Replace shell runner examples with `pytest ...` or `python -m tests.cmdscripts...`.
  - [ ] Document zero-shell rule.
  - [ ] Document how command-line tool tests are written in Python.
  - [ ] Document registry logs and manifest paths.

- [ ] `README.md`
  - [ ] Replace references to `tests/run_*.sh` with pytest/Python entry points.
  - [ ] Link to `tests/configs/REGISTRY_MIGRATION.md`.

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

- [ ] `tests/run_af_family_conf.sh` -> `tests/cmdscripts/af_family_conf.py` + `tests/test_cmd_af_family_conf.py` + delete shell.
- [ ] `tests/run_cache_pblock_pblock.sh` -> `tests/cmdscripts/cache_pblock_pblock.py` + `tests/test_cmd_cache_pblock_pblock.py` + delete shell.
- [ ] `tests/run_credential_http_bearer.sh` -> `tests/cmdscripts/credential_http_bearer.py` + `tests/test_cmd_credential_http_bearer.py` + delete shell.
- [ ] `tests/run_credential_webdav_xroot.sh` -> `tests/cmdscripts/credential_webdav_xroot.py` + `tests/test_cmd_credential_webdav_xroot.py` + delete shell.
- [ ] `tests/run_credential_xroot_gsi.sh` -> `tests/cmdscripts/credential_xroot_gsi.py` + `tests/test_cmd_credential_xroot_gsi.py` + delete shell.
- [ ] `tests/run_dashboard_vfs_browse.sh` -> `tests/cmdscripts/dashboard_vfs_browse.py` + `tests/test_cmd_dashboard_vfs_browse.py` + delete shell.
- [ ] `tests/cvmfs/run_matrix.sh` -> `tests/cmdscripts/cvmfs_matrix.py` + `tests/test_cvmfs_matrix.py` + delete shell.
- [ ] `tests/c/run_vfs_caps_tests.sh` -> `tests/cmdscripts/c_vfs_caps.py` + `tests/test_c_vfs_caps.py` + delete shell.
- [ ] `tests/ceph/run_sd_ceph_live.sh` -> `tests/cmdscripts/ceph_sd_ceph_live.py` + `tests/test_ceph_sd_ceph_live.py` + delete shell.
- [ ] `tests/unit/run_tests.sh` -> `tests/cmdscripts/unit_tests.py` + `tests/test_cmd_unit_tests.py` + delete shell.
- [ ] `tests/fuzz/run_all.sh` -> `tests/cmdscripts/fuzz_all.py` + `tests/test_cmd_fuzz_all.py` + delete shell.

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

- [ ] `tests/guard/run_guard_core.sh` -> `tests/lib_py/guard_core.py` + pytest module
  - [ ] Compile/run guard helper from Python.
  - [ ] Delete shell runner.

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
| `tests/ceph_harness.sh` | `tests/cmdscripts/ceph_harness.py` + pytest tests | Port harness setup to Python, delete shell. |
| `tests/frm_fake_mss.sh` | `tests/lib_py/frm_fake_mss.py` | Port fake MSS behavior to Python executable/helper, delete shell. |
| `tests/fwd_b_token_forward_probe.sh` | `tests/cmdscripts/fwd_b_token_forward_probe.py` + pytest test | Port probe to Python, delete shell. |

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
- [ ] Delete shell runner.

### Wave 1: Skeleton And Guardrails

- [ ] Add registry and launcher.
- [ ] Add marker and conftest integration.
- [ ] Add manifest support.
- [ ] Add smoke test.
- [ ] Add lint in warn-only mode.
- [ ] Convert `tests/run_af_family_conf.sh` as first Python-managed command proof.
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
