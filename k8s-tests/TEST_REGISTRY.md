# nginx-xrootd Test Registry

Flat registry of every test file in the module's suite (`tests/`): its test-function count, what it exercises, and the file in the k8s test lab that replicates it. The k8s lab runs a 1:1 fork of each file at `k8s-tests/remote-suite/tests/<same name>` (conftest REMOTE mode, against a deployed brix server); the **Status** column says how that fork runs.

**Totals:** 390 files · 4979 test functions (`def test_*`; parametrized cases expand further at runtime). Regenerate with `python3 k8s-tests/tools/gen-test-registry.py`.

**k8s fork status legend:**
- `pure-remote` — runs over the wire unchanged (no edit).
- `adapted` — edited to run remotely; server-side files reached via `klib.svc_*` (`# brix-remote-adapted`).
- `verified-ok` — runs remotely as-is, verified (`# brix-remote-ok`).
- `remote-skip` — needs a multi-server topology the single mega server can't provide (`# brix-remote-skip`).

**Status counts:** `pure-remote` 267 · `adapted` 25 · `verified-ok` 29 · `remote-skip` 69

| # | Test file (`tests/`) | Tests | What it tests | k8s lab file (`remote-suite/tests/`) | Status |
|---|---|------:|---|---|---|
| 1 | `test_a_robustness.py` | 36 | kXR_ping header with dlen=1_000_000 (no payload follows) | `test_a_robustness.py` | `remote-skip` |
| 2 | `test_a_robustness_b.py` | 7 | Read once — must succeed | `test_a_robustness_b.py` | `adapted` |
| 3 | `test_a_upstream_redirect.py` | 7 | Tests for upstream XRootD redirector support (kXR_redirect, kXR_wait, | `test_a_upstream_redirect.py` | `pure-remote` |
| 4 | `test_a_webdav_clients.py` | 4 | Functional tests exercising WebDAV uploads/downloads using xrdcp | `test_a_webdav_clients.py` | `remote-skip` |
| 5 | `test_acc.py` | 10 | XrdAcc-compatible authorization engine (brix_authdb_format xrdacc) | `test_acc.py` | `verified-ok` |
| 6 | `test_acc_residual.py` | 12 | residual XrdAcc parity gaps closed after the M0–M8 port | `test_acc_residual.py` | `pure-remote` |
| 7 | `test_access_log_batch.py` | 4 | Phase 33 C1 — batched access logging | `test_access_log_batch.py` | `pure-remote` |
| 8 | `test_aio.py` | 11 | Tests for the AIO (async I/O) subsystem -- nginx thread-pool pread/pwrite path | `test_aio.py` | `verified-ok` |
| 9 | `test_aio_waitresp.py` | 6 | Async-engine deferred-reply handling (client/lib/aio_io.c) | `test_aio_waitresp.py` | `pure-remote` |
| 10 | `test_arc_guard.py` | 7 | Phase-65 bad-actor guard — ARC profile (ngx_http_brix_guard_module) | `test_arc_guard.py` | `pure-remote` |
| 11 | `test_async_operations.py` | 13 | Tests for async operations and kXR_attn unsolicited notifications | `test_async_operations.py` | `pure-remote` |
| 12 | `test_attack_vectors.py` | 14 | Web-facing attack-vector hardening tests that complement test_evil_paths.py | `test_attack_vectors.py` | `pure-remote` |
| 13 | `test_authdb.py` | 9 | authdb enforcement tests: verify that brix_authdb restricts access | `test_authdb.py` | `remote-skip` |
| 14 | `test_build_hardening.py` | 2 | Asserts the build emits position-independent, RELRO+BIND_NOW, non-exec-stack | `test_build_hardening.py` | `pure-remote` |
| 15 | `test_cache_lock_reclaim.py` | 1 | regression wrapper for cache-fill lock | `test_cache_lock_reclaim.py` | `pure-remote` |
| 16 | `test_cache_partial_fill.py` | 16 | Read-cache partial-fill behavior across modular backends. See | `test_cache_partial_fill.py` | `pure-remote` |
| 17 | `test_cache_reap_metrics.py` | 1 | Integration test for the cache stale-dirty reaper's per-reason Prometheus | `test_cache_reap_metrics.py` | `pure-remote` |
| 18 | `test_cache_write_through.py` | 11 | Cache and Write-Through server integration tests | `test_cache_write_through.py` | `remote-skip` |
| 19 | `test_chaos_mesh.py` | 6 | Chaos Mesh integration tests from docs/comprehensive-testing-roadmap.md | `test_chaos_mesh.py` | `remote-skip` |
| 20 | `test_chaos_mixed_auth.py` | 5 | Chaos test for a small mesh of nginx-xrootd instances whose UPSTREAM auth | `test_chaos_mixed_auth.py` | `pure-remote` |
| 21 | `test_checksum_on_write.py` | 3 | §8.3 checksum-on-ingest (WebDAV PUT) | `test_checksum_on_write.py` | `pure-remote` |
| 22 | `test_chkpoint_stock_framing.py` | 15 | kXR_ckpXeq stock wire-framing parity | `test_chkpoint_stock_framing.py` | `remote-skip` |
| 23 | `test_client_async_tpc.py` | 3 | Native-client async response handling (phase-37 §16 gap B) | `test_client_async_tpc.py` | `pure-remote` |
| 24 | `test_client_autorefresh.py` | 3 | Phase 40 (b) — native client (xrdcp --auto-refresh) credential auto-acquire | `test_client_autorefresh.py` | `verified-ok` |
| 25 | `test_client_cred_preflight.py` | 4 | Phase 40 (c) — client-side credential pre-flight diagnostics | `test_client_cred_preflight.py` | `pure-remote` |
| 26 | `test_client_gaps.py` | 7 | Native-client gap closures (phase-37 §16): capabilities the clients previously | `test_client_gaps.py` | `pure-remote` |
| 27 | `test_client_robustness.py` | 7 | Phase 40 (a) — native client (xrdcp) robustness edges | `test_client_robustness.py` | `verified-ok` |
| 28 | `test_client_web_transfer.py` | 18 | Native-client production transfer over web schemes (phase-37 §16 gap A) | `test_client_web_transfer.py` | `pure-remote` |
| 29 | `test_client_xrd_doctor_login.py` | 4 | xrd doctor + xrd login — cross-tool UX verbs on the unified front-end | `test_client_xrd_doctor_login.py` | `pure-remote` |
| 30 | `test_client_xrd_frontend.py` | 8 | The unified xrd git-style front-end: one command dispatching to xrdcp/xrdfs/xrddiag | `test_client_xrd_frontend.py` | `pure-remote` |
| 31 | `test_client_xrd_mount.py` | 8 | xrd mount / xrd unmount — FUSE3 driver + fusermount front-end verbs | `test_client_xrd_mount.py` | `pure-remote` |
| 32 | `test_client_xrdcp_bulk.py` | 16 | xrdcp bulk/batch transfer (swiss-army-knife cluster 2, slice 1) | `test_client_xrdcp_bulk.py` | `remote-skip` |
| 33 | `test_client_xrdfs_eos_x509.py` | 5 | native xrdfs read-only commands over GSI | `test_client_xrdfs_eos_x509.py` | `pure-remote` |
| 34 | `test_client_xrdfs_tools.py` | 7 | xrdfs power tools (swiss-army-knife cluster 1): recursive filesystem ergonomics | `test_client_xrdfs_tools.py` | `pure-remote` |
| 35 | `test_client_xrdfs_web.py` | 5 | native xrdfs over an http(s)/WebDAV endpoint | `test_client_xrdfs_web.py` | `remote-skip` |
| 36 | `test_client_xrdrc_alias.py` | 6 | ~/.xrdrc endpoint aliases (swiss-army-knife "just works" UX): name an endpoint once | `test_client_xrdrc_alias.py` | `pure-remote` |
| 37 | `test_clientconf_cksum.py` | 2 | Client-conformance: xrdadler32 + xrdcrc32c (differential vs stock) | `test_clientconf_cksum.py` | `pure-remote` |
| 38 | `test_clientconf_narrative.py` | 4 | Client-conformance: narrative (stateful) scenarios | `test_clientconf_narrative.py` | `pure-remote` |
| 39 | `test_clientconf_surface.py` | 9 | Client-conformance: CLI-surface coverage | `test_clientconf_surface.py` | `pure-remote` |
| 40 | `test_clientconf_xrdcp.py` | 1 | Client-conformance: xrdcp transfer tool (differential vs stock) | `test_clientconf_xrdcp.py` | `pure-remote` |
| 41 | `test_clientconf_xrdfs.py` | 1 | Client-conformance: xrdfs metadata tool (differential vs stock) | `test_clientconf_xrdfs.py` | `pure-remote` |
| 42 | `test_clientconf_xrdgsiproxy.py` | 3 | Client-conformance: xrdgsiproxy (differential vs stock) | `test_clientconf_xrdgsiproxy.py` | `pure-remote` |
| 43 | `test_clientconf_xrdmapc.py` | 3 | Client-conformance: xrdmapc (differential vs stock) | `test_clientconf_xrdmapc.py` | `pure-remote` |
| 44 | `test_cms.py` | 8 | Tests for the CMS manager heartbeat/registration subsystem | `test_cms.py` | `pure-remote` |
| 45 | `test_cms_fast_settle.py` | 4 | guards the CMS mesh fast cold-start settling work | `test_cms_fast_settle.py` | `pure-remote` |
| 46 | `test_cms_mesh_interop.py` | 29 | Real XRootD <-> nginx-xrootd CMS mesh interoperability tests | `test_cms_mesh_interop.py` | `pure-remote` |
| 47 | `test_cms_resilience.py` | 8 | Phase 50 CMS network-fault resilience | `test_cms_resilience.py` | `pure-remote` |
| 48 | `test_cms_state_have_select.py` | 12 | CMS on-demand selection wire conformance | `test_cms_state_have_select.py` | `pure-remote` |
| 49 | `test_cms_wire_pup_conformance.py` | 24 | CMS manager-protocol Pup/frame | `test_cms_wire_pup_conformance.py` | `pure-remote` |
| 50 | `test_cns.py` | 2 | §6 Composite Cluster Name Space (2-node, real instances) | `test_cns.py` | `pure-remote` |
| 51 | `test_compression_build_matrix.py` | 3 | Phase-42 build matrix — graceful degradation + real dynamic-module dlopen | `test_compression_build_matrix.py` | `pure-remote` |
| 52 | `test_compression_cleanroom_lint.py` | 3 | Phase-42 cross-cutting guardrails — clean-room + no-goto + docblock lint | `test_compression_cleanroom_lint.py` | `pure-remote` |
| 53 | `test_compression_fuse_resilience.py` | 3 | phase-42 W4 inline read compression through | `test_compression_fuse_resilience.py` | `verified-ok` |
| 54 | `test_compression_inbound.py` | 4 | Phase-42 W1 — inbound (PUT) decompression over WebDAV | `test_compression_inbound.py` | `pure-remote` |
| 55 | `test_compression_inbound_adversarial.py` | 6 | Phase-42 W1 — inbound (PUT) decompression over WebDAV: ADVERSARIAL cases | `test_compression_inbound_adversarial.py` | `pure-remote` |
| 56 | `test_compression_inbound_bomb_trailing.py` | 4 | Phase-42 W1 — inbound (PUT) decompression GAPS: per-codec bomb guards, | `test_compression_inbound_bomb_trailing.py` | `pure-remote` |
| 57 | `test_compression_negotiation_gaps.py` | 7 | Phase-42 W2 — outbound (GET) compression NEGOTIATION gaps | `test_compression_negotiation_gaps.py` | `pure-remote` |
| 58 | `test_compression_outbound.py` | 4 | Phase-42 W2 — outbound (GET) response compression | `test_compression_outbound.py` | `pure-remote` |
| 59 | `test_compression_root.py` | 4 | Phase-42 W4 — root:// inline read compression (server + native client) | `test_compression_root.py` | `pure-remote` |
| 60 | `test_compression_root_adversarial.py` | 5 | Phase-42 W4 — root:// inline read compression: adversarial / functional suite | `test_compression_root_adversarial.py` | `pure-remote` |
| 61 | `test_compression_root_edge.py` | 10 | Phase-42 W4 EDGE cases for root:// inline | `test_compression_root_edge.py` | `pure-remote` |
| 62 | `test_compression_root_invariant.py` | 6 | Phase-42 W4 PLAINTEXT invariant for | `test_compression_root_invariant.py` | `pure-remote` |
| 63 | `test_compression_s3_chunked_codec.py` | 4 | GAP AWSCHUNK-CE — S3 aws-chunked upload that ALSO names an inner Content-Encoding | `test_compression_s3_chunked_codec.py` | `pure-remote` |
| 64 | `test_compression_s3_inbound.py` | 4 | Phase-42 W1 — inbound (PUT) decompression over the S3 REST gateway | `test_compression_s3_inbound.py` | `pure-remote` |
| 65 | `test_compression_s3_outbound.py` | 4 | Phase-42 W2 — outbound (GET) response compression on the S3 surface | `test_compression_s3_outbound.py` | `pure-remote` |
| 66 | `test_compression_write.py` | 6 | Phase-42 W5 — root:// inline WRITE compression (client compresses each kXR_write | `test_compression_write.py` | `pure-remote` |
| 67 | `test_compression_write_adversarial.py` | 7 | Phase-42 W5 adversarial coverage of | `test_compression_write_adversarial.py` | `pure-remote` |
| 68 | `test_compression_zcrc32_extended.py` | 8 | Extended zcrc32 / crc32 checksum coverage against the shared harness | `test_compression_zcrc32_extended.py` | `pure-remote` |
| 69 | `test_compression_zip.py` | 3 | Phase-42 W3 — ZIP archive member reads over root:// (client-side, zlib-only) | `test_compression_zip.py` | `pure-remote` |
| 70 | `test_concurrent.py` | 16 | Concurrent transfer tests for nginx-xrootd | `test_concurrent.py` | `remote-skip` |
| 71 | `test_conf_cksum.py` | 24 | Differential CHECKSUM conformance: the stock XRootD client (xrdfs/xrdcp) | `test_conf_cksum.py` | `pure-remote` |
| 72 | `test_conf_client.py` | 22 | Conformance: OUR native client vs the STOCK xrootd server (Q2), plus STOCK | `test_conf_client.py` | `pure-remote` |
| 73 | `test_conf_client2.py` | 29 | =========================================================================== # | `test_conf_client2.py` | `pure-remote` |
| 74 | `test_conf_client2_b.py` | 28 | --------------------------------------------------------------------------- # | `test_conf_client2_b.py` | `verified-ok` |
| 75 | `test_conf_dirlist.py` | 34 | Differential conformance for directory listing (kXR_dirlist) | `test_conf_dirlist.py` | `pure-remote` |
| 76 | `test_conf_errors.py` | 31 | the dir must still exist on disk either way | `test_conf_errors.py` | `pure-remote` |
| 77 | `test_conf_errors_b.py` | 31 | mv onto an existing directory name: pin the success/failure CLASS to STOCK | `test_conf_errors_b.py` | `pure-remote` |
| 78 | `test_conf_fattr.py` | 14 | both must have stored & returned it | `test_conf_fattr.py` | `pure-remote` |
| 79 | `test_conf_fattr_b.py` | 13 | =========================================================================== # | `test_conf_fattr_b.py` | `pure-remote` |
| 80 | `test_conf_framing.py` | 30 | A one-sided hang is normally the bug — EXCEPT for kXR_sigver, which by | `test_conf_framing.py` | `pure-remote` |
| 81 | `test_conf_framing_b.py` | 30 | =========================================================================== # | `test_conf_framing_b.py` | `pure-remote` |
| 82 | `test_conf_gfal_ops.py` | 29 | Differential gfal2 conformance — nginx-xrootd vs stock xrootd v5.x | `test_conf_gfal_ops.py` | `pure-remote` |
| 83 | `test_conf_io_read.py` | 11 | Differential READ data-plane conformance: stock XRootD client (xrdcp/xrdfs) | `test_conf_io_read.py` | `pure-remote` |
| 84 | `test_conf_openflags.py` | 25 | Differential conformance for the kXR_open FLAGS MATRIX and RESPONSE shape | `test_conf_openflags.py` | `pure-remote` |
| 85 | `test_conf_pathedge.py` | 50 | Differential conformance for PATH & NAME edge cases | `test_conf_pathedge.py` | `pure-remote` |
| 86 | `test_conf_paths.py` | 32 | Differential conformance for PATH handling + namespace confinement | `test_conf_paths.py` | `pure-remote` |
| 87 | `test_conf_pgio.py` | 12 | =========================================================================== | `test_conf_pgio.py` | `pure-remote` |
| 88 | `test_conf_pgio_b.py` | 12 | =========================================================================== | `test_conf_pgio_b.py` | `pure-remote` |
| 89 | `test_conf_prepfattr.py` | 16 | =========================================================================== # | `test_conf_prepfattr.py` | `pure-remote` |
| 90 | `test_conf_prepfattr_b.py` | 16 | set+get on each server independently, compare the get output | `test_conf_prepfattr_b.py` | `pure-remote` |
| 91 | `test_conf_query2.py` | 44 | Differential conformance for kXR_query across ALL its reqcodes — stock XrdCl | `test_conf_query2.py` | `pure-remote` |
| 92 | `test_conf_query_errors.py` | 16 | Differential conformance for kXR_query (config/checksum/stats/space) and | `test_conf_query_errors.py` | `pure-remote` |
| 93 | `test_conf_readv.py` | 19 | Differential VECTOR-READ (kXR_readv) and read-offset/EOF conformance | `test_conf_readv.py` | `pure-remote` |
| 94 | `test_conf_rename.py` | 24 | =========================================================================== # | `test_conf_rename.py` | `pure-remote` |
| 95 | `test_conf_rename_b.py` | 24 | =========================================================================== # | `test_conf_rename_b.py` | `verified-ok` |
| 96 | `test_conf_sequences.py` | 19 | Differential conformance for STATEFUL OP SEQUENCES and end-to-end integrity | `test_conf_sequences.py` | `pure-remote` |
| 97 | `test_conf_sessions.py` | 20 | =========================================================================== # | `test_conf_sessions.py` | `pure-remote` |
| 98 | `test_conf_sessions_b.py` | 19 | =========================================================================== # | `test_conf_sessions_b.py` | `pure-remote` |
| 99 | `test_conf_stat.py` | 19 | Differential conformance for stat / ls / statvfs / locate | `test_conf_stat.py` | `pure-remote` |
| 100 | `test_conf_stattypes.py` | 13 | =========================================================================== # | `test_conf_stattypes.py` | `pure-remote` |
| 101 | `test_conf_stattypes_b.py` | 13 | =========================================================================== # | `test_conf_stattypes_b.py` | `pure-remote` |
| 102 | `test_conf_statx.py` | 22 | Differential conformance for kXR_statx, stat-by-HANDLE vs PATH, statvfs/vfs, | `test_conf_statx.py` | `pure-remote` |
| 103 | `test_conf_truncate_sync.py` | 21 | Differential conformance for TRUNCATE / SYNC / SPARSE / partial I/O / large-file size matrix | `test_conf_truncate_sync.py` | `pure-remote` |
| 104 | `test_conf_write.py` | 22 | Differential conformance for the kXR_write DATA PLANE | `test_conf_write.py` | `pure-remote` |
| 105 | `test_conf_write_ops.py` | 27 | Differential conformance for WRITE / namespace-mutation ops | `test_conf_write_ops.py` | `pure-remote` |
| 106 | `test_conf_xrdcl_fileops.py` | 24 | Differential XrdCl::File conformance via the REAL libXrdCl bindings | `test_conf_xrdcl_fileops.py` | `pure-remote` |
| 107 | `test_conf_xrdcl_fs.py` | 42 | Differential conformance: XrdCl::FileSystem metadata / namespace ops | `test_conf_xrdcl_fs.py` | `pure-remote` |
| 108 | `test_conf_xrdcl_locate.py` | 43 | Differential conformance for XrdCl::FileSystem locate / deeplocate / query — | `test_conf_xrdcl_locate.py` | `pure-remote` |
| 109 | `test_conf_xrdcl_stat.py` | 41 | Differential conformance for XrdCl::FileSystem.stat / statvfs driven through the | `test_conf_xrdcl_stat.py` | `pure-remote` |
| 110 | `test_conf_xrdcp.py` | 33 | Differential conformance for xrdcp OPTION breadth, RECURSIVE copies, | `test_conf_xrdcp.py` | `pure-remote` |
| 111 | `test_conf_xrdfs.py` | 48 | Breadth-first differential conformance across EVERY xrdfs subcommand | `test_conf_xrdfs.py` | `pure-remote` |
| 112 | `test_conformance.py` | 28 | Protocol conformance tests: compare nginx-xrootd plugin responses to an | `test_conformance.py` | `remote-skip` |
| 113 | `test_conformance_topologies.py` | 3 | run the FULL conformance suite through | `test_conformance_topologies.py` | `remote-skip` |
| 114 | `test_conftest_fleet_lifecycle.py` | 5 | Unit coverage for the conftest "own only the fleet we started" guard | `test_conftest_fleet_lifecycle.py` | `remote-skip` |
| 115 | `test_crc64.py` | 7 | CRC64 cross-protocol integration tests (this gateway's crc64 = CRC-64/XZ, | `test_crc64.py` | `pure-remote` |
| 116 | `test_credential_translation.py` | 6 | Credential Translation Bridge — Section 4C of the comprehensive testing roadmap | `test_credential_translation.py` | `adapted` |
| 117 | `test_crl.py` | 14 | Certificate Revocation List (CRL) tests | `test_crl.py` | `remote-skip` |
| 118 | `test_cross_protocol_access_logging.py` | 3 | Protocol-labelled HTTP access logging | `test_cross_protocol_access_logging.py` | `pure-remote` |
| 119 | `test_cross_protocol_shared_helpers.py` | 15 | Phase 55: local-object copy moved behind the shared VFS copy entry point | `test_cross_protocol_shared_helpers.py` | `pure-remote` |
| 120 | `test_cross_protocol_shared_helpers_b.py` | 14 | auth_gate.c is the canonical consumer of all three tiers; handlers that | `test_cross_protocol_shared_helpers_b.py` | `pure-remote` |
| 121 | `test_cvmfs_harness.py` | 2 | tests/test_cvmfs_harness.py | `test_cvmfs_harness.py` | `pure-remote` |
| 122 | `test_cvmfs_mock.py` | 6 | tests/test_cvmfs_mock.py | `test_cvmfs_mock.py` | `pure-remote` |
| 123 | `test_dashboard.py` | 18 | HTTPS dashboard API tests | `test_dashboard.py` | `pure-remote` |
| 124 | `test_dashboard_config_anon.py` | 8 | Dashboard config-download + anonymous-tier security tests | `test_dashboard_config_anon.py` | `pure-remote` |
| 125 | `test_dashboard_files.py` | 8 | Admin file browser/downloader on the monitoring dashboard | `test_dashboard_files.py` | `pure-remote` |
| 126 | `test_deep_tree_special_files.py` | 9 | Regression guard: deep-nested + symlink data-plane access, and the | `test_deep_tree_special_files.py` | `pure-remote` |
| 127 | `test_dig.py` | 7 | §3 XrdDig remote diagnostics (security-first) | `test_dig.py` | `pure-remote` |
| 128 | `test_dropin_byte_for_byte.py` | 21 | drop-in byte-for-byte parity vs the | `test_dropin_byte_for_byte.py` | `pure-remote` |
| 129 | `test_e2e_cluster_matrix.py` | 11 | Heterogeneous cluster interoperability matrix — Section 3B of the comprehensive | `test_e2e_cluster_matrix.py` | `remote-skip` |
| 130 | `test_e2e_proxy_matrix.py` | 11 | End-to-end proxy interoperability matrix — Section 3A of the comprehensive | `test_e2e_proxy_matrix.py` | `remote-skip` |
| 131 | `test_e2e_redirector_xrdcp.py` | 9 | End-to-end tests: nginx CMS redirector → xrootd data server via xrdcp | `test_e2e_redirector_xrdcp.py` | `remote-skip` |
| 132 | `test_endsess_session_scope.py` | 2 | kXR_endsess must be session-scoped | `test_endsess_session_scope.py` | `pure-remote` |
| 133 | `test_evil_actor.py` | 5 | adversarial worker-crash hunt for the root:// stream plane | `test_evil_actor.py` | `pure-remote` |
| 134 | `test_evil_actor_v2.py` | 8 | deeper adversarial worker-crash / data-race hunt | `test_evil_actor_v2.py` | `verified-ok` |
| 135 | `test_evil_actor_v3.py` | 4 | login + small whole-file read over TLS | `test_evil_actor_v3.py` | `pure-remote` |
| 136 | `test_evil_actor_v3_b.py` | 4 | Reuse ONE nearline file: its first open posts a recall, and while that recall | `test_evil_actor_v3_b.py` | `pure-remote` |
| 137 | `test_evil_paths.py` | 21 | "Truly evil" path-confinement security tests across EVERY protocol the module | `test_evil_paths.py` | `adapted` |
| 138 | `test_fail2ban_regex.py` | 5 | Phase-65 fail2ban deliverables — filter regexes vs the sample audit log | `test_fail2ban_regex.py` | `pure-remote` |
| 139 | `test_fattr_query.py` | 25 | Functional tests for | `test_fattr_query.py` | `adapted` |
| 140 | `test_federated_redirection.py` | 5 | Federated redirection (WAN/Global Namespace) — Section 4B of the comprehensive | `test_federated_redirection.py` | `remote-skip` |
| 141 | `test_file_api.py` | 43 | --------------------------------------------------------------------------- | `test_file_api.py` | `pure-remote` |
| 142 | `test_file_api_b.py` | 29 | --------------------------------------------------------------------------- | `test_file_api_b.py` | `pure-remote` |
| 143 | `test_frm_async.py` | 2 | Phase 35 / Phase 3 — async stage completion (kXR_waitresp → kXR_attn asynresp) | `test_frm_async.py` | `verified-ok` |
| 144 | `test_frm_control_locality.py` | 3 | control-dir residency locality semantics | `test_frm_control_locality.py` | `pure-remote` |
| 145 | `test_frm_owner.py` | 5 | FINDING-FRM-1 regression: the FRM cancel/evict path must enforce requester | `test_frm_owner.py` | `pure-remote` |
| 146 | `test_frm_phase1_http.py` | 4 | Phase 35 / Phase 1 remainder — HTTP residency reporting + Prometheus metrics | `test_frm_phase1_http.py` | `pure-remote` |
| 147 | `test_frm_phase4.py` | 3 | Phase 35 / Phase 4 — optional parity (F1-F6) | `test_frm_phase4.py` | `pure-remote` |
| 148 | `test_frm_phase4_engines.py` | 3 | Phase 35 / Phase 4 engines — F3 (residency-cmd oracle) + F5 (checksum-on-stage), | `test_frm_phase4_engines.py` | `verified-ok` |
| 149 | `test_frm_queue.py` | 7 | Phase 35 / Phase 0 — FRM durable stage-request queue (src/frm/) | `test_frm_queue.py` | `pure-remote` |
| 150 | `test_frm_scratch.py` | 5 | FRM materialize-to-scratch + control-dir prototype | `test_frm_scratch.py` | `verified-ok` |
| 151 | `test_frm_staging.py` | 6 | Phase 35 / Phase 1 — the usable synchronous tape gateway (stream face) | `test_frm_staging.py` | `verified-ok` |
| 152 | `test_fs_ops.py` | 20 | Filesystem operation tests for nginx-xrootd: mkdir, rmdir, rm, mv, chmod | `test_fs_ops.py` | `adapted` |
| 153 | `test_gfal_interop.py` | 2 | GFAL2 interop — the WLCG data-access layer (FTS/Rucio) against nginx-xrootd | `test_gfal_interop.py` | `pure-remote` |
| 154 | `test_gohep_interop.py` | 9 | go-hep interop regression guards | `test_gohep_interop.py` | `pure-remote` |
| 155 | `test_gsi_bridge.py` | 13 | Cross-server GSI transfer tests: copy files between an official xrootd server | `test_gsi_bridge.py` | `remote-skip` |
| 156 | `test_gsi_cipher.py` | 1 | Unit vectors for the shared XrdCryptosslCipher-compatible GSI primitives | `test_gsi_cipher.py` | `pure-remote` |
| 157 | `test_gsi_concurrency.py` | 6 | Phase 33 — GSI handshake concurrency (the plain-GSI :11095 wedge) | `test_gsi_concurrency.py` | `remote-skip` |
| 158 | `test_gsi_handshake.py` | 43 | 5 MiB: the session cipher must hold over thousands of AES-CBC blocks | `test_gsi_handshake.py` | `pure-remote` |
| 159 | `test_gsi_handshake_b.py` | 27 | local → our nginx | `test_gsi_handshake_b.py` | `pure-remote` |
| 160 | `test_gsi_interop_guards.py` | 9 | GSI interoperability guards — keep nginx-xrootd talking GSI to real XRootD | `test_gsi_interop_guards.py` | `pure-remote` |
| 161 | `test_gsi_proxy_crypto.py` | 1 | phase-57 §F6 — compile + run the standalone GSI proxy-delegation crypto suite | `test_gsi_proxy_crypto.py` | `pure-remote` |
| 162 | `test_gsi_security.py` | 50 | GSI authentication security tests for nginx-xrootd | `test_gsi_security.py` | `remote-skip` |
| 163 | `test_gsi_tls.py` | 31 | Functional read tests for root:// with GSI authentication + in-protocol TLS | `test_gsi_tls.py` | `remote-skip` |
| 164 | `test_guard_endpoints.py` | 15 | Phase-65 bad-actor guard — coverage across every protocol front door | `test_guard_endpoints.py` | `pure-remote` |
| 165 | `test_ha_failover.py` | 5 | Site-Entry High-Availability (HA) Stack — Section 4E of the comprehensive | `test_ha_failover.py` | `remote-skip` |
| 166 | `test_handshake_protocol_wire.py` | 16 | raw-wire conformance of the XRootD | `test_handshake_protocol_wire.py` | `pure-remote` |
| 167 | `test_health_endpoint.py` | 4 | phase-47 W2: the /healthz liveness/readiness probe | `test_health_endpoint.py` | `pure-remote` |
| 168 | `test_host_auth.py` | 2 | XRootD host (host-based) auth — Phase 52 WS-C | `test_host_auth.py` | `pure-remote` |
| 169 | `test_http_cache_hit.py` | 8 | Section 3.1 — HTTP read-through cache hit tests | `test_http_cache_hit.py` | `remote-skip` |
| 170 | `test_http_origin_stall_timeout.py` | 2 | guard: the libcurl cache-origin transport | `test_http_origin_stall_timeout.py` | `pure-remote` |
| 171 | `test_http_webdav.py` | 10 | Plain HTTP WebDAV tests (no TLS, anonymous access) | `test_http_webdav.py` | `pure-remote` |
| 172 | `test_http_webdav_lock.py` | 11 | WebDAV LOCK and UNLOCK tests for the ngx_http_brix_webdav_module | `test_http_webdav_lock.py` | `pure-remote` |
| 173 | `test_http_webdav_lock_recursive.py` | 5 | Lock the destination | `test_http_webdav_lock_recursive.py` | `verified-ok` |
| 174 | `test_http_webdav_status_codes.py` | 51 | --------------------------------------------------------------------------- | `test_http_webdav_status_codes.py` | `pure-remote` |
| 175 | `test_http_webdav_status_codes_b.py` | 48 | --------------------------------------------------------------------------- | `test_http_webdav_status_codes_b.py` | `pure-remote` |
| 176 | `test_https_webdav_status_codes.py` | 71 | Comprehensive HTTPS status-code and RFC compliance tests for the TLS WebDAV | `test_https_webdav_status_codes.py` | `pure-remote` |
| 177 | `test_https_webdav_token_status_codes.py` | 71 | Comprehensive HTTPS status-code and RFC compliance tests for the TLS WebDAV | `test_https_webdav_token_status_codes.py` | `pure-remote` |
| 178 | `test_hybrid_mesh.py` | 9 | exercise the hybrid two-tier cross-backend mesh | `test_hybrid_mesh.py` | `pure-remote` |
| 179 | `test_impersonate_idmap.py` | 1 | unit tests for the phase-40 idmap layer | `test_impersonate_idmap.py` | `pure-remote` |
| 180 | `test_integrity_matrix.py` | 10 | cross-topology data-integrity matrix | `test_integrity_matrix.py` | `remote-skip` |
| 181 | `test_interop_io.py` | 25 | Conformance tests for I/O operations comparing nginx-xrootd against the | `test_interop_io.py` | `remote-skip` |
| 182 | `test_interop_namespace.py` | 25 | Conformance tests for filesystem namespace operations comparing nginx-xrootd | `test_interop_namespace.py` | `remote-skip` |
| 183 | `test_interop_query.py` | 36 | Conformance tests for kXR_query subtypes, kXR_prepare semantics, open-flag | `test_interop_query.py` | `remote-skip` |
| 184 | `test_io_edge_cases.py` | 30 | Read starting at exactly file_size → 0 bytes, kXR_ok | `test_io_edge_cases.py` | `pure-remote` |
| 185 | `test_io_edge_cases_b.py` | 20 | File unchanged if write was accepted | `test_io_edge_cases_b.py` | `pure-remote` |
| 186 | `test_ipv6_admin_ratelimit_metrics.py` | 16 | Phase 36 §7.2.7 — dashboard / admin API / rate-limit / metrics over IPv6 | `test_ipv6_admin_ratelimit_metrics.py` | `pure-remote` |
| 187 | `test_ipv6_cms_redirect.py` | 15 | phase-36 §7.2.2: CMS clustering + redirect to | `test_ipv6_cms_redirect.py` | `pure-remote` |
| 188 | `test_ipv6_fallback.py` | 7 | client IPv6→IPv4 auto-downgrade on dual-stack hosts | `test_ipv6_fallback.py` | `pure-remote` |
| 189 | `test_ipv6_s3.py` | 12 | Phase-36 §7.2.5 — S3 object storage over IPv6 (HTTP client) | `test_ipv6_s3.py` | `remote-skip` |
| 190 | `test_ipv6_tpc.py` | 8 | Phase-36 §7.2.6: native + WebDAV third-party-copy (TPC) | `test_ipv6_tpc.py` | `remote-skip` |
| 191 | `test_ipv6_webdav_proxy.py` | 11 | Phase 36 §7.2.4 — WebDAV proxy with an IPv6 backend (the GATING bracket-on-emit suite) | `test_ipv6_webdav_proxy.py` | `remote-skip` |
| 192 | `test_ipv6_webdav_xrdhttp.py` | 20 | Phase-36 §7.2.3 — WebDAV / XrdHttp over IPv6 (HTTP client) | `test_ipv6_webdav_xrdhttp.py` | `remote-skip` |
| 193 | `test_ipv6_xrootd_stream.py` | 12 | root:// XRootD stream over IPv6 (raw-wire) | `test_ipv6_xrootd_stream.py` | `remote-skip` |
| 194 | `test_krb5_auth.py` | 5 | Kerberos 5 (krb5) authentication for the root:// stream tier | `test_krb5_auth.py` | `remote-skip` |
| 195 | `test_large_file_metrics.py` | 5 | Large-file correctness and metrics integration tests (Section 12) | `test_large_file_metrics.py` | `verified-ok` |
| 196 | `test_large_offset_wire.py` | 16 | large / extreme byte-offset wire conformance | `test_large_offset_wire.py` | `verified-ok` |
| 197 | `test_libbrix.py` | 4 | Public libbrix library (phase-37 §14.1): install + pkg-config + sample consumer | `test_libbrix.py` | `remote-skip` |
| 198 | `test_lifecycle_speed.py` | 4 | guards the startup/shutdown speed work | `test_lifecycle_speed.py` | `pure-remote` |
| 199 | `test_macaroon_delegation.py` | 19 | Macaroon third-party delegation endpoint tests | `test_macaroon_delegation.py` | `pure-remote` |
| 200 | `test_macaroon_discharge.py` | 23 | Discharge Macaroon bundle validation tests | `test_macaroon_discharge.py` | `pure-remote` |
| 201 | `test_macaroon_negative.py` | 5 | Coverage gap #6 (test-coverage-gap-audit): server-side macaroon REJECTION | `test_macaroon_negative.py` | `pure-remote` |
| 202 | `test_macaroon_request.py` | 4 | §2 dCache/XrdMacaroons "application/macaroon-request" | `test_macaroon_request.py` | `pure-remote` |
| 203 | `test_malicious_credentials.py` | 22 | Cross-protocol "malicious credential" hardening tests.  A bad actor controls the | `test_malicious_credentials.py` | `pure-remote` |
| 204 | `test_manager_mode.py` | 28 | Tests for manager-mode XRootD redirector functionality | `test_manager_mode.py` | `remote-skip` |
| 205 | `test_metadata_stress.py` | 9 | Metadata-operation STRESS test — hammer the server with paced ~100 req/s of | `test_metadata_stress.py` | `pure-remote` |
| 206 | `test_metrics.py` | 14 | Prometheus metrics endpoint tests for nginx-xrootd | `test_metrics.py` | `pure-remote` |
| 207 | `test_metrics_coverage_root.py` | 23 | Prometheus coverage for the root:// data plane | `test_metrics_coverage_root.py` | `remote-skip` |
| 208 | `test_metrics_coverage_s3.py` | 8 | Prometheus coverage for the S3 object lifecycle | `test_metrics_coverage_s3.py` | `pure-remote` |
| 209 | `test_metrics_coverage_webdav.py` | 9 | Prometheus coverage for WebDAV file lifecycle | `test_metrics_coverage_webdav.py` | `pure-remote` |
| 210 | `test_metrics_vfs_ops.py` | 4 | Prometheus coverage for the VFS sweep's new op labels | `test_metrics_vfs_ops.py` | `pure-remote` |
| 211 | `test_mirror_upstream.py` | 14 | nginx+xrootd traffic mirror in front of a | `test_mirror_upstream.py` | `pure-remote` |
| 212 | `test_native_client_conformance.py` | 7 | Conformance gate (phase-37 M10): the native xrdcp/xrdfs vs the system tools | `test_native_client_conformance.py` | `remote-skip` |
| 213 | `test_native_client_diagnostics.py` | 11 | Native client diagnostics (phase-37 §15): --wire-trace, --timing, xrdfs explain | `test_native_client_diagnostics.py` | `pure-remote` |
| 214 | `test_native_gsi_interop.py` | 6 | Native-client GSI interop against a REAL XrdSecgsi server (phase-48) | `test_native_gsi_interop.py` | `pure-remote` |
| 215 | `test_native_krb5.py` | 7 | Native Kerberos 5 (krb5) auth — phase-37 §6 + §14.3 | `test_native_krb5.py` | `pure-remote` |
| 216 | `test_native_sss.py` | 6 | Native SSS (Simple Shared Secret) auth — phase-37 §6 + §14.3 | `test_native_sss.py` | `pure-remote` |
| 217 | `test_native_tools.py` | 11 | Native Tier-1 tools (phase-37 §14): xrdcrc32c, xrdadler32, xrdqstats, wait41, | `test_native_tools.py` | `verified-ok` |
| 218 | `test_native_xrdcp_xrdfs.py` | 27 | -------------------------------------------------------------------------- | `test_native_xrdcp_xrdfs.py` | `remote-skip` |
| 219 | `test_native_xrdcp_xrdfs_b.py` | 26 | --- M9 error / security-negative --- | `test_native_xrdcp_xrdfs_b.py` | `verified-ok` |
| 220 | `test_net_resilience.py` | 3 | client hardening against a misbehaving firewall | `test_net_resilience.py` | `pure-remote` |
| 221 | `test_netfault_stream.py` | 5 | Phase 39 — network-fault resilience, stream (root://) plane | `test_netfault_stream.py` | `pure-remote` |
| 222 | `test_new_opcodes.py` | 22 | --------------------------------------------------------------------------- | `test_new_opcodes.py` | `pure-remote` |
| 223 | `test_new_opcodes_b.py` | 33 | ── low-level helpers ──────────────────────────────────────────────── | `test_new_opcodes_b.py` | `pure-remote` |
| 224 | `test_ocsp.py` | 8 | OCSP certificate revocation checking and stapling tests | `test_ocsp.py` | `pure-remote` |
| 225 | `test_official_interop.py` | 36 | Differential conformance against the STOCK XRootD server and client | `test_official_interop.py` | `pure-remote` |
| 226 | `test_official_xrootd_resilience.py` | 5 | this repo's FUSE client vs a REAL XRootD | `test_official_xrootd_resilience.py` | `pure-remote` |
| 227 | `test_opcode_coverage.py` | 1 | Exact kXR_... mention in any test file | `test_opcode_coverage.py` | `pure-remote` |
| 228 | `test_opcode_flag_coverage.py` | 9 | Focused wire-level coverage for XRootD option flags that do not have their | `test_opcode_flag_coverage.py` | `adapted` |
| 229 | `test_open_flags_lifecycle.py` | 12 | raw-wire conformance for kXR_open flags | `test_open_flags_lifecycle.py` | `remote-skip` |
| 230 | `test_path_confinement.py` | 15 | Path-confinement security tests for the kernel-enforced export-root boundary | `test_path_confinement.py` | `adapted` |
| 231 | `test_path_depth_guards.py` | 5 | Recursive walk guards — prevention of CPU exhaustion from excessive path depth | `test_path_depth_guards.py` | `verified-ok` |
| 232 | `test_pgread_wire_conformance.py` | 11 | raw-wire kXR_pgread (3030) protocol | `test_pgread_wire_conformance.py` | `remote-skip` |
| 233 | `test_pgwrite_checksum.py` | 15 | Raw-protocol tests for kXR_pgwrite CRC32c checksum verification | `test_pgwrite_checksum.py` | `adapted` |
| 234 | `test_pgwrite_cse.py` | 19 | Raw-protocol tests for the kXR_pgwrite CSE (checksum-error) retransmit machine | `test_pgwrite_cse.py` | `remote-skip` |
| 235 | `test_phase0_guardrails.py` | 7 | Phase 0 source-reduction guardrail inventory | `test_phase0_guardrails.py` | `pure-remote` |
| 236 | `test_phase1_commodity_libraries.py` | 5 | Phase 1 commodity-library inventory | `test_phase1_commodity_libraries.py` | `pure-remote` |
| 237 | `test_phase20_kv_shm.py` | 9 | Phase 20 — shared-memory KV store, caches, and rate limiting | `test_phase20_kv_shm.py` | `verified-ok` |
| 238 | `test_phase21_proxy_filter.py` | 14 | Phase 21 — multi-backend WebDAV proxy (Step D) and XrdHttp filters (Steps A/B) | `test_phase21_proxy_filter.py` | `remote-skip` |
| 239 | `test_phase22_health_check.py` | 9 | Phase 22 — active stream health checks | `test_phase22_health_check.py` | `pure-remote` |
| 240 | `test_phase23_admin_api.py` | 14 | Phase 23 — dynamic upstreams: REST admin write API + dynamic WebDAV proxy pool | `test_phase23_admin_api.py` | `pure-remote` |
| 241 | `test_phase24_mirror.py` | 21 | Phase 24 — traffic mirroring (HTTP/WebDAV + XRootD stream) | `test_phase24_mirror.py` | `pure-remote` |
| 242 | `test_phase25_ratelimit.py` | 23 | Phase 25 — advanced rate limiting & traffic shaping | `test_phase25_ratelimit.py` | `pure-remote` |
| 243 | `test_phase27_memsafety.py` | 12 | Phase 27 — memory-safety & anti-abuse hardening | `test_phase27_memsafety.py` | `pure-remote` |
| 244 | `test_phase31_memory.py` | 6 | Phase 31 — memory-budget streaming regression tests | `test_phase31_memory.py` | `pure-remote` |
| 245 | `test_phase51_resilience.py` | 3 | phase-51 cross-protocol resilience wiring | `test_phase51_resilience.py` | `pure-remote` |
| 246 | `test_plan6_guardrails.py` | 9 | Plan 6 source-layer guardrail inventory | `test_plan6_guardrails.py` | `pure-remote` |
| 247 | `test_pmark.py` | 3 | SciTags packet marking (phase-34) end-to-end firefly tests | `test_pmark.py` | `pure-remote` |
| 248 | `test_prepare_staging.py` | 20 | Tests for kXR_prepare — tape staging / cache hint opcode | `test_prepare_staging.py` | `remote-skip` |
| 249 | `test_privilege_escalation.py` | 50 | Privilege escalation and authorization boundary tests for nginx-xrootd | `test_privilege_escalation.py` | `remote-skip` |
| 250 | `test_propfind_infinity.py` | 8 | Integration tests for PROPFIND Depth: infinity (Feature 4) | `test_propfind_infinity.py` | `pure-remote` |
| 251 | `test_protocol_edge_cases.py` | 18 | Protocol conformance edge cases for nginx-xrootd | `test_protocol_edge_cases.py` | `adapted` |
| 252 | `test_protocol_flags.py` | 31 | Phase 1 capability-flags tests | `test_protocol_flags.py` | `pure-remote` |
| 253 | `test_proxy_large_read.py` | 1 | guards the brix_proxy large-read forwarding path | `test_proxy_large_read.py` | `pure-remote` |
| 254 | `test_proxy_mode.py` | 39 | ────────────────────────────────────────────────────────────────────────────── | `test_proxy_mode.py` | `pure-remote` |
| 255 | `test_proxy_mode_b.py` | 28 | The upstream may return ok or redirect; both are valid responses | `test_proxy_mode_b.py` | `pure-remote` |
| 256 | `test_proxy_protocol_edges.py` | 6 | First failure is the saturation error — assert it is clean | `test_proxy_protocol_edges.py` | `pure-remote` |
| 257 | `test_proxy_protocol_edges_b.py` | 5 | Multiple streamed frames were reassembled, in upstream order | `test_proxy_protocol_edges_b.py` | `pure-remote` |
| 258 | `test_put_content_encoding.py` | 3 | Coverage gap #4 (test-coverage-gap-audit): Content-Encoding gzip/deflate | `test_put_content_encoding.py` | `pure-remote` |
| 259 | `test_pwd_auth.py` | 5 | XRootD pwd (XrdSecpwd) password-auth — Phase 52 WS-B | `test_pwd_auth.py` | `pure-remote` |
| 260 | `test_python_api_surface.py` | 13 | Implementation of the Python API Deep-Surface Cross-Backend Test Plan | `test_python_api_surface.py` | `adapted` |
| 261 | `test_query.py` | 18 | kXR_query tests — checksum and space-usage queries | `test_query.py` | `pure-remote` |
| 262 | `test_query_extended.py` | 44 | Query infotypes with zero coverage: Qconfig keys, Qvisa, Qopaque, | `test_query_extended.py` | `adapted` |
| 263 | `test_query_token.py` | 6 | §1 HTTP bearer token via ?authz= query parameter | `test_query_token.py` | `remote-skip` |
| 264 | `test_ratelimit_gauge_reset.py` | 1 | regression wrapper for rate-limit in-use | `test_ratelimit_gauge_reset.py` | `pure-remote` |
| 265 | `test_readonly_http_endpoint.py` | 9 | Read-only ENDPOINT enforcement for the HTTP protocols (WebDAV + S3) | `test_readonly_http_endpoint.py` | `remote-skip` |
| 266 | `test_readv.py` | 10 | kXR_readv (vector / scatter-gather read) tests | `test_readv.py` | `pure-remote` |
| 267 | `test_readv_security.py` | 29 | vector-read and paged (chunked) read/write | `test_readv_security.py` | `adapted` |
| 268 | `test_readv_segment_size.py` | 2 | Verifies the brix_readv_segment_size directive (the per-kXR_readv-element cap, | `test_readv_segment_size.py` | `pure-remote` |
| 269 | `test_readv_variable_blocks.py` | 2 | Verify THIS PROJECT'S native client (libbrix, brix_file_readv) correctly handles | `test_readv_variable_blocks.py` | `pure-remote` |
| 270 | `test_recover_wrts.py` | 4 | kXR_recoverWrts write-recovery journal tests | `test_recover_wrts.py` | `remote-skip` |
| 271 | `test_reload.py` | 6 | Reload semantics — nginx -s reload makes new module settings live for NEW | `test_reload.py` | `pure-remote` |
| 272 | `test_root_tpc.py` | 11 | Native root:// third-party-copy (TPC) coverage for the nginx stream plugin | `test_root_tpc.py` | `remote-skip` |
| 273 | `test_s3.py` | 31 | S3-compatible object storage tests | `test_s3.py` | `pure-remote` |
| 274 | `test_s3_auth_oracle.py` | 3 | Coverage gap #1 (test-coverage-gap-audit): S3 SigV4 must not be an | `test_s3_auth_oracle.py` | `pure-remote` |
| 275 | `test_s3_bucket_ops.py` | 6 | S3 bucket-level operations (phase-43 W2) | `test_s3_bucket_ops.py` | `pure-remote` |
| 276 | `test_s3_checksums.py` | 9 | S3 multi-algorithm full-object checksums (phase-43 W1) | `test_s3_checksums.py` | `adapted` |
| 277 | `test_s3_chunk_signature.py` | 3 | S3 aws-chunked per-chunk SigV4 signature verification (phase-47 W6a) | `test_s3_chunk_signature.py` | `remote-skip` |
| 278 | `test_s3_conditional.py` | 21 | S3 conditional requests + response-header overrides (phase-43 W3) | `test_s3_conditional.py` | `pure-remote` |
| 279 | `test_s3_create_exclusive.py` | 3 | S3 atomic create-if-absent — PutObject with If-None-Match: * (phase-47 W6b) | `test_s3_create_exclusive.py` | `pure-remote` |
| 280 | `test_s3_list_cache.py` | 3 | S3 ListObjects per-worker sorted-listing cache (phase-47 W6c) | `test_s3_list_cache.py` | `pure-remote` |
| 281 | `test_s3_metrics.py` | 10 | Prometheus metrics tests for the S3-compatible protocol layer | `test_s3_metrics.py` | `pure-remote` |
| 282 | `test_s3_multipart.py` | 13 | S3 Multipart Upload integration tests | `test_s3_multipart.py` | `pure-remote` |
| 283 | `test_s3_perf_characterization.py` | 2 | S3 data-plane performance characterization (phase-45) | `test_s3_perf_characterization.py` | `pure-remote` |
| 284 | `test_s3_presigned.py` | 13 | SigV4 authentication tests for S3 presigned URLs | `test_s3_presigned.py` | `verified-ok` |
| 285 | `test_s3_status_codes.py` | 53 | Comprehensive HTTP status-code and S3 API compliance tests for the S3-compatible | `test_s3_status_codes.py` | `verified-ok` |
| 286 | `test_s3_streaming.py` | 8 | S3 aws-chunked streaming upload decode (phase-43 W0) | `test_s3_streaming.py` | `pure-remote` |
| 287 | `test_s3_tagging.py` | 9 | S3 object tagging + canned subresources (phase-43 W5) | `test_s3_tagging.py` | `pure-remote` |
| 288 | `test_s3_upload_part_copy_traversal.py` | 4 | Coverage gap #15 (test-coverage-gap-audit): S3 UploadPartCopy | `test_s3_upload_part_copy_traversal.py` | `remote-skip` |
| 289 | `test_s3_xrootd_gateway.py` | 9 | S3-to-XRootD Gateway interoperability — Section 4D of the comprehensive testing | `test_s3_xrootd_gateway.py` | `verified-ok` |
| 290 | `test_sanitizer_smoke.py` | 1 | Sanitizer smoke lane: drive a minimal read round-trip through a SANITIZE=1 | `test_sanitizer_smoke.py` | `remote-skip` |
| 291 | `test_scan.py` | 15 | Storage-scan engine (src/fs/scan/) — phase-2 base engine | `test_scan.py` | `pure-remote` |
| 292 | `test_sd_ceph.py` | 1 | Compile + run the standalone Ceph driver path-mapping suite | `test_sd_ceph.py` | `pure-remote` |
| 293 | `test_security_hardening.py` | 9 | Security hardening regressions for nginx-xrootd | `test_security_hardening.py` | `adapted` |
| 294 | `test_security_level.py` | 3 | Security-level negotiation and default enforcement behavior | `test_security_level.py` | `pure-remote` |
| 295 | `test_security_redteam.py` | 9 | Phase 28 adversarial-hardening regression suite | `test_security_redteam.py` | `pure-remote` |
| 296 | `test_session_bind.py` | 11 | Tests for kXR_bind — secondary data channel attachment to an existing session | `test_session_bind.py` | `adapted` |
| 297 | `test_session_lifecycle_wire.py` | 17 | raw-wire conformance for the XRootD | `test_session_lifecycle_wire.py` | `pure-remote` |
| 298 | `test_shm_fork_safety.py` | 2 | cross-protocol regression for the SHM/fork SIGSEGV bug | `test_shm_fork_safety.py` | `pure-remote` |
| 299 | `test_shm_mutex_recovery.py` | 1 | regression wrapper for the SHM table-mutex | `test_shm_mutex_recovery.py` | `pure-remote` |
| 300 | `test_shm_slab_safety_lint.py` | 7 | static guard against reintroducing the SHM/fork bug | `test_shm_slab_safety_lint.py` | `pure-remote` |
| 301 | `test_shutdown_resume.py` | 6 | Fast worker teardown + mid-transfer resume across an nginx reload/restart | `test_shutdown_resume.py` | `pure-remote` |
| 302 | `test_sigver_verify.py` | 7 | Tests for kXR_sigver — request signing envelope verification | `test_sigver_verify.py` | `pure-remote` |
| 303 | `test_sigver_wire_conformance.py` | 12 | raw-wire conformance for kXR_sigver | `test_sigver_wire_conformance.py` | `adapted` |
| 304 | `test_slice_cache.py` | 21 | Phase 26 slice-granular caching tests | `test_slice_cache.py` | `pure-remote` |
| 305 | `test_source_guards.py` | 1 | Static source-tree guards (no nginx required) | `test_source_guards.py` | `pure-remote` |
| 306 | `test_srr_endpoint.py` | 5 | WLCG Storage Resource Reporting (SRR) endpoint — src/protocols/srr/ | `test_srr_endpoint.py` | `pure-remote` |
| 307 | `test_ssi.py` | 4 | §7 minimal unary XrdSsi over root:// (raw wire, real instance) | `test_ssi.py` | `pure-remote` |
| 308 | `test_ssi_alerts.py` | 1 | Phase-3 out-of-band alert delivery for SSI | `test_ssi_alerts.py` | `pure-remote` |
| 309 | `test_ssi_async.py` | 3 | Phase-2 async server-push (kXR_attn) for SSI | `test_ssi_async.py` | `pure-remote` |
| 310 | `test_ssi_config.py` | 4 | Phase-6 SSI config directives | `test_ssi_config.py` | `pure-remote` |
| 311 | `test_ssi_cta.py` | 4 | Phase-5 end-to-end: the flagship CTA SSI service | `test_ssi_cta.py` | `pure-remote` |
| 312 | `test_ssi_metrics.py` | 3 | Phase-6 SSI metrics | `test_ssi_metrics.py` | `pure-remote` |
| 313 | `test_ssi_multiplex.py` | 3 | two (and more) concurrent reqIds on one open | `test_ssi_multiplex.py` | `pure-remote` |
| 314 | `test_ssi_stream.py` | 1 | Phase-3 streamed async responses for SSI | `test_ssi_stream.py` | `pure-remote` |
| 315 | `test_ssi_wire.py` | 8 | byte-exact XrdSsi-over-xroot conformance for the nginx | `test_ssi_wire.py` | `pure-remote` |
| 316 | `test_storage_backend_panel.py` | 4 | Backend Storage observability tests (spec 2026-07-03) | `test_storage_backend_panel.py` | `pure-remote` |
| 317 | `test_storascan.py` | 6 | xrdstorascan — the backend-aware storage admin tool (phase 1: verify + bench) | `test_storascan.py` | `remote-skip` |
| 318 | `test_stream_guard.py` | 4 | Phase-65 bad-actor guard — root:// stream relay (brix_guard_stream) | `test_stream_guard.py` | `pure-remote` |
| 319 | `test_tape_rest.py` | 4 | Phase 35 / Phase 2 — WLCG HTTP Tape REST API (src/protocols/webdav/tape_rest.c) | `test_tape_rest.py` | `pure-remote` |
| 320 | `test_throughput.py` | 5 | Throughput test: stream a 200 MB file through the nginx-xrootd module and | `test_throughput.py` | `remote-skip` |
| 321 | `test_token_aud_array.py` | 6 | Coverage gap #30 (test-coverage-gap-audit): JWT aud claim as a JSON ARRAY | `test_token_aud_array.py` | `pure-remote` |
| 322 | `test_token_auth.py` | 32 | JWT/WLCG bearer-token authentication tests for nginx-xrootd | `test_token_auth.py` | `adapted` |
| 323 | `test_token_cache_l1.py` | 4 | per-worker L1 token-validation cache (phase-50) | `test_token_cache_l1.py` | `adapted` |
| 324 | `test_token_es256.py` | 3 | Coverage gap #9 (test-coverage-gap-audit): ES256 / EC P-256 POSITIVE JWT verify | `test_token_es256.py` | `pure-remote` |
| 325 | `test_token_jwks_refresh.py` | 4 | Integration tests for JWKS mtime-poll hot refresh (Feature 3) | `test_token_jwks_refresh.py` | `verified-ok` |
| 326 | `test_token_macaroon.py` | 11 | Macaroon-based authentication tests | `test_token_macaroon.py` | `pure-remote` |
| 327 | `test_token_security.py` | 59 | JWT token security edge cases: algorithm confusion, nbf boundary, | `test_token_security.py` | `adapted` |
| 328 | `test_tpc_async_open.py` | 1 | W1 / phase-57 §F8 gate: the native TPC destination resolves an ASYNCHRONOUS | `test_tpc_async_open.py` | `pure-remote` |
| 329 | `test_tpc_delegation.py` | 4 | phase-57 §F6 interop GATE — a stock xrootd GSI source with X.509 proxy | `test_tpc_delegation.py` | `pure-remote` |
| 330 | `test_tpc_gsi_nginx_source.py` | 1 | W1 end-to-end gate: native root:// TPC PULL where the nginx DESTINATION | `test_tpc_gsi_nginx_source.py` | `pure-remote` |
| 331 | `test_tpc_gsi_outbound.py` | 1 | Local verification of the server-outbound TPC GSI handshake (src/tpc/gsi/gsi_outbound_*.c) | `test_tpc_gsi_outbound.py` | `pure-remote` |
| 332 | `test_tpc_ssrf_policy.py` | 14 | Tests for the brix_tpc_allow_local and brix_tpc_allow_private | `test_tpc_ssrf_policy.py` | `pure-remote` |
| 333 | `test_tpc_tls.py` | 1 | phase-57 §F5 gate: native root:// TPC PULL where the DESTINATION upgrades the | `test_tpc_tls.py` | `pure-remote` |
| 334 | `test_tpc_token_mode.py` | 10 | Tests for the native XRootD TPC OAuth2/OIDC token delegation opaque parameter | `test_tpc_token_mode.py` | `pure-remote` |
| 335 | `test_upstream_auth_multiround.py` | 1 | phase-57 §F4/W1.4.a gate: the upstream cache-fill bootstrap survives a | `test_upstream_auth_multiround.py` | `pure-remote` |
| 336 | `test_valgrind_regression.py` | 5 | Phase 27 W6c — regression guards for the two Valgrind-Memcheck-found defects, | `test_valgrind_regression.py` | `pure-remote` |
| 337 | `test_vo_acl.py` | 31 | VO ACL enforcement tests: verify that brix_require_vo restricts access | `test_vo_acl.py` | `remote-skip` |
| 338 | `test_webdav.py` | 60 | HTTPS WebDAV module tests for the ngx_http_brix_webdav_module | `test_webdav.py` | `adapted` |
| 339 | `test_webdav_auth_cache.py` | 3 | WebDAV x509 authentication cache tests | `test_webdav_auth_cache.py` | `remote-skip` |
| 340 | `test_webdav_delete_lock_security.py` | 11 | Protocol-conformance + security tests for the WebDAV namespace/lock surface | `test_webdav_delete_lock_security.py` | `remote-skip` |
| 341 | `test_webdav_http_security.py` | 57 | HTTP/WebDAV security and protocol-conformance tests | `test_webdav_http_security.py` | `remote-skip` |
| 342 | `test_webdav_lock_startup_sweep.py` | 3 | WebDAV lock startup sweep (brix_webdav_lock_startup_sweep) | `test_webdav_lock_startup_sweep.py` | `pure-remote` |
| 343 | `test_webdav_metrics.py` | 13 | Prometheus metrics tests for the WebDAV protocol layer | `test_webdav_metrics.py` | `remote-skip` |
| 344 | `test_webdav_spooled_put.py` | 1 | Regression test for WebDAV PUT bodies that nginx spools to a temp file | `test_webdav_spooled_put.py` | `remote-skip` |
| 345 | `test_webdav_tpc.py` | 19 | HTTP third-party-copy integration tests for the nginx WebDAV plugin | `test_webdav_tpc.py` | `remote-skip` |
| 346 | `test_webdav_tpc_cred.py` | 11 | HTTP-TPC OAuth2/OIDC credential delegation integration tests | `test_webdav_tpc_cred.py` | `remote-skip` |
| 347 | `test_webdav_unlock_ownership.py` | 5 | Coverage gap #7 (test-coverage-gap-audit): WebDAV UNLOCK ownership boundary | `test_webdav_unlock_ownership.py` | `remote-skip` |
| 348 | `test_webdav_voms.py` | 3 | Section 2.2 — VOMS VO/FQAN extraction for WebDAV tests | `test_webdav_voms.py` | `remote-skip` |
| 349 | `test_wire_protocol_security.py` | 54 | Wire protocol security: stream ID echo, malformed dlen, unknown opcodes, | `test_wire_protocol_security.py` | `adapted` |
| 350 | `test_wlcg_audit_log.py` | 10 | WLCG Audit Log Verification — Section 9 / Phase 4 of the comprehensive testing | `test_wlcg_audit_log.py` | `verified-ok` |
| 351 | `test_write.py` | 8 | Write / upload tests for nginx-xrootd anonymous mode | `test_write.py` | `adapted` |
| 352 | `test_write_recovery.py` | 1 | kXR_recoverWrts (write recovery) functional tests | `test_write_recovery.py` | `verified-ok` |
| 353 | `test_writev_stock_framing.py` | 6 | kXR_writev stock wire-framing parity | `test_writev_stock_framing.py` | `adapted` |
| 354 | `test_xfer_ledger.py` | 4 | Unified durable-transfer audit ledger (src/fs/xfer/xfer_ledger.c) | `test_xfer_ledger.py` | `remote-skip` |
| 355 | `test_xfer_resume_sweep.py` | 1 | Phase 6 housekeeping — TTL sweep of abandoned upload-resume partials | `test_xfer_resume_sweep.py` | `pure-remote` |
| 356 | `test_xfer_spawn.py` | 1 | Compile + run the standalone crash-safe reparented command runner suite | `test_xfer_spawn.py` | `pure-remote` |
| 357 | `test_xfer_wt_journal.py` | 1 | Phase 4b-2 — write-through async flush is recorded in the shared durable | `test_xfer_wt_journal.py` | `pure-remote` |
| 358 | `test_xfer_wt_replay.py` | 1 | Phase 4b-2b-ii — write-through durable-flush REPLAY across a restart | `test_xfer_wt_replay.py` | `pure-remote` |
| 359 | `test_xrd_busybox.py` | 56 | Phase-41 BusyBox-style POSIX verbs on the unified xrd front-end | `test_xrd_busybox.py` | `pure-remote` |
| 360 | `test_xrdckverify.py` | 9 | the xrdckverify on-disk checksum-verify tool | `test_xrdckverify.py` | `pure-remote` |
| 361 | `test_xrdcp_client_options.py` | 6 | Official xrdcp client-option coverage for the nginx-xrootd root:// endpoint | `test_xrdcp_client_options.py` | `pure-remote` |
| 362 | `test_xrdcp_root_anon_compare.py` | 1 | Functional test: compare xrdcp downloads from the anonymous (no-auth) | `test_xrdcp_root_anon_compare.py` | `remote-skip` |
| 363 | `test_xrddiag.py` | 16 | xrddiag (phase-37 §15.3–15.7): the consolidated deployment-diagnostic CLI | `test_xrddiag.py` | `remote-skip` |
| 364 | `test_xrddiag_capture.py` | 4 | Session capture / replay (phase-37 §15.1): the .xrdcap bundle | `test_xrddiag_capture.py` | `pure-remote` |
| 365 | `test_xrddiag_compare_davs.py` | 3 | xrddiag compare --davs (phase-37 §15.6): the cross-protocol consistency oracle | `test_xrddiag_compare_davs.py` | `pure-remote` |
| 366 | `test_xrddiag_multiproto.py` | 11 | xrddiag remote-doctor (phase-37 §15.10): multi-protocol transfer deep-dive | `test_xrddiag_multiproto.py` | `pure-remote` |
| 367 | `test_xrddiag_probe.py` | 5 | xrddiag probe-robustness (phase-37 §15.8): a gated adversarial auditor | `test_xrddiag_probe.py` | `pure-remote` |
| 368 | `test_xrddiag_remote_doctor.py` | 20 | xrddiag remote-doctor (phase-37 §15.8): network transfer-problem diagnostician | `test_xrddiag_remote_doctor.py` | `remote-skip` |
| 369 | `test_xrddiag_watch.py` | 4 | xrddiag watch — continuous health/SLA probe loop | `test_xrddiag_watch.py` | `pure-remote` |
| 370 | `test_xrdgsiproxy.py` | 7 | Native xrdgsiproxy (phase-37 §14.3): RFC-3820 X.509 proxy create/info/destroy | `test_xrdgsiproxy.py` | `pure-remote` |
| 371 | `test_xrdhttp.py` | 28 | XrdHttp protocol extension tests | `test_xrdhttp.py` | `pure-remote` |
| 372 | `test_xrdhttp_auth.py` | 6 | Auth Conformance Tests for XrdHttp/davs:// | `test_xrdhttp_auth.py` | `adapted` |
| 373 | `test_xrdhttp_conformance.py` | 8 | XrdHttp conformance edge cases — path confinement, auth boundaries, and | `test_xrdhttp_conformance.py` | `pure-remote` |
| 374 | `test_xrdhttp_guard.py` | 4 | Phase-65 bad-actor guard — XrdHttp/WebDAV profile parity | `test_xrdhttp_guard.py` | `pure-remote` |
| 375 | `test_xrdhttp_tpc.py` | 5 | HTTP-TPC Conformance Tests | `test_xrdhttp_tpc.py` | `remote-skip` |
| 376 | `test_xrdhttp_wait_retry_digest_range.py` | 11 | XrdHttp/WebDAV HTTP-plane | `test_xrdhttp_wait_retry_digest_range.py` | `remote-skip` |
| 377 | `test_xrdhttp_webdav.py` | 17 | Cross-backend WebDAV conformance tests for nginx-xrootd vs reference xrootd XrdHttp | `test_xrdhttp_webdav.py` | `pure-remote` |
| 378 | `test_xrdmapc.py` | 7 | xrdmapc (phase-37 §14.5 / §15.4): cluster-map tool + ghost-replica detector | `test_xrdmapc.py` | `pure-remote` |
| 379 | `test_xrootd.py` | 25 | Tests for nginx-xrootd stream module | `test_xrootd.py` | `adapted` |
| 380 | `test_xrootd_conformance.py` | 20 | XRootD wire-protocol CONFORMANCE tests — grounded in the C++ reference | `test_xrootd_conformance.py` | `pure-remote` |
| 381 | `test_xrootd_performance_conformance.py` | 18 | serial: latency/throughput-vs-reference assertions — invalid under pool load | `test_xrootd_performance_conformance.py` | `pure-remote` |
| 382 | `test_xrootd_performance_conformance_b.py` | 18 | Warm both backends before timing thread-pool fanout | `test_xrootd_performance_conformance_b.py` | `pure-remote` |
| 383 | `test_xrootdfs.py` | 16 | xrootdfs (FUSE mount) + libbrixposix_preload.so (LD_PRELOAD POSIX shim) — phase-37 | `test_xrootdfs.py` | `verified-ok` |
| 384 | `test_xrootdfs_ext.py` | 6 | M5: vendor POSIX-extension ops through the FUSE mount | `test_xrootdfs_ext.py` | `verified-ok` |
| 385 | `test_xrootdfs_http.py` | 10 | HTTP(S)/WebDAV transport for the xrootdfs FUSE driver | `test_xrootdfs_http.py` | `verified-ok` |
| 386 | `test_xrootdfs_resilience.py` | 4 | M6: network-resilience tests for xrootdfs | `test_xrootdfs_resilience.py` | `verified-ok` |
| 387 | `test_zcrc32_checksum.py` | 3 | zcrc32 checksum parity across the root:// surface (native client + server) | `test_zcrc32_checksum.py` | `pure-remote` |
| 388 | `test_zip_member.py` | 17 | Server-side root:// ZIP member access (phase-57 W2): ?xrdcl.unzip=<member> | `test_zip_member.py` | `pure-remote` |
| 389 | `test_zip_scratch.py` | 2 | ZIP CONSUME via materialize-to-scratch (Pillar F #3) | `test_zip_scratch.py` | `pure-remote` |
| 390 | `test_zip_write.py` | 3 | Phase-42 W3 (write) — xrdcp ZIP writer end-to-end | `test_zip_write.py` | `pure-remote` |
