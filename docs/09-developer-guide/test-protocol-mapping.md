# Test-to-Protocol Mapping

This document maps the testing suite in `tests/` to the XRootD protocol specification.

| Test File | Protocol Area | Description | Backend Compatibility |
| :--- | :--- | :--- | :--- |
| `backend_matrix.py` | Infrastructure | Test backend matrix config | Agnostic |
| `cms_parent_stubs.py` | Cluster/Manager | Stubs for CMS tests | Agnostic |
| `conftest.py` | Infrastructure | Pytest configuration | Agnostic |
| `__init__.py` | Infrastructure | Python init | Agnostic |
| `pki_helpers.py` | Security | PKI test helpers | Agnostic |
| `test_aio.py` | I/O/Async | Asynchronous I/O | Agnostic |
| `test_a_robustness.py` | Robustness | System robustness tests | Agnostic |
| `test_async_operations.py` | I/O/Async | Async operations | Agnostic |
| `test_a_upstream_redirect.py` | Redirection | Upstream redirection | Agnostic |
| `test_authdb.py` | Auth | Authentication DB | Agnostic |
| `test_chaos_mesh.py` | Robustness | Chaos engineering | Agnostic |
| `test_cms.py` | Cluster/Manager | Cluster management | Agnostic |
| `test_concurrent.py` | Concurrency | Concurrent operations | Agnostic |
| `test_conformance.py` | Protocol | Protocol conformance | Agnostic |
| `test_credential_translation.py` | Auth/Security | Credential translation | Agnostic |
| `test_cross_protocol_shared_helpers.py` | Infrastructure | Shared test helpers | Agnostic |
| `test_e2e_cluster_matrix.py` | Cluster | E2E cluster matrix | Agnostic |
| `test_e2e_proxy_matrix.py` | Proxy | E2E proxy matrix | Agnostic |
| `test_fattr_query.py` | FS/Meta | File attribute query | Agnostic |
| `test_federated_redirection.py` | Redirection | Federated redirection | Agnostic |
| `test_file_api.py` | I/O/FS | File API | Agnostic |
| `test_fs_ops.py` | FS | File system ops | Agnostic |
| `test_gsi_security.py` | Security/GSI | GSI security | Agnostic |
| `test_gsi_tls.py` | Security/TLS | GSI over TLS | Agnostic |
| `test_ha_failover.py` | Robustness | High Availability | Agnostic |
| `test_https_webdav_status_codes.py` | WebDAV | HTTPS status codes | Agnostic |
| `test_https_webdav_token_status_codes.py` | WebDAV/Auth | HTTPS token status codes | Agnostic |
| `test_http_webdav.py` | WebDAV | WebDAV operations | Agnostic |
| `test_http_webdav_status_codes.py` | WebDAV | HTTP status codes | Agnostic |
| `test_interop_io.py` | I/O | I/O interoperability | Agnostic |
| `test_interop_namespace.py` | Namespace | Namespace interop | Agnostic |
| `test_io_edge_cases.py` | I/O | I/O edge cases | Agnostic |
| `test_large_file_metrics.py` | Metrics | Large file metrics | Agnostic |
| `test_macaroon_delegation.py` | Auth/Macaroon | Macaroon delegation | Agnostic |
| `test_macaroon_discharge.py` | Auth/Macaroon | Macaroon discharge | Agnostic |
| `test_new_opcodes.py` | Protocol/Opcode | New XRootD opcodes | Agnostic |
| `test_ocsp.py` | Security/TLS | OCSP stapling | Agnostic |
| `test_opcode_coverage.py` | Protocol/Opcode | Opcode coverage | Agnostic |
| `test_opcode_flag_coverage.py` | Protocol/Opcode | Opcode flag coverage | Agnostic |
| `test_pgwrite_checksum.py` | I/O/Protocol | Page-write checksums | Agnostic |
| `test_phase0_guardrails.py` | Infrastructure | Phase 0 guardrails | Agnostic |
| `test_phase1_commodity_libraries.py` | Infrastructure | Phase 1 libs | Agnostic |
| `test_plan6_guardrails.py` | Infrastructure | Plan 6 guardrails | Agnostic |
| `test_prepare_staging.py` | Protocol/Staging | Data staging | Agnostic |
| `test_privilege_escalation.py` | Security | Privilege escalation | Agnostic |
| `test_propfind_infinity.py` | WebDAV | WebDAV PROPFIND infinity | Agnostic |
| `test_protocol_edge_cases.py` | Protocol | Protocol edge cases | Agnostic |
| `test_protocol_flags.py` | Protocol | Protocol flags | Agnostic |
| `test_python_api_surface.py` | API | Python API surface | Agnostic |
| `test_query_extended.py` | Protocol/Query | Extended queries | Agnostic |
| `test_query.py` | Protocol/Query | Query ops | Agnostic |
| `test_readv.py` | I/O | Vector reads | Agnostic |
| `test_recover_wrts.py` | I/O/Recovery | Write recovery | Agnostic |
| `test_root_tpc.py` | TPC | Native TPC | Agnostic |
| `test_s3_multipart.py` | S3 | S3 multipart | Agnostic |
| `test_s3_presigned.py` | S3 | S3 presigned | Agnostic |
| `test_s3.py` | S3 REST | S3 functionality | Agnostic |
| `test_s3_status_codes.py` | S3 | S3 status codes | Agnostic |
| `test_security_hardening.py` | Security | Security hardening | Agnostic |
| `test_security_level.py` | Security | Security levels | Agnostic |
| `test_session_bind.py` | Session/Handshake | Bind/Login | Agnostic |
| `test_sigver_verify.py` | Security | Signature verification | Agnostic |
| `test_throughput.py` | Metrics | Throughput metrics | Agnostic |
| `test_token_auth.py` | Auth | Token auth | Agnostic |
| `test_token_jwks_refresh.py` | Auth | JWKS refresh | Agnostic |
| `test_token_macaroon.py` | Auth/Macaroon | Macaroon tokens | Agnostic |
| `test_token_security.py` | Auth/Security | Token security | Agnostic |
| `test_tpc_ssrf_policy.py` | TPC/Security | TPC SSRF | Agnostic |
| `test_tpc_token_mode.py` | TPC/Auth | TPC token mode | Agnostic |
| `test_webdav.py` | WebDAV | WebDAV ops | Agnostic |
| `test_webdav_tpc.py` | WebDAV/TPC | WebDAV TPC | Agnostic |
| `test_webdav_voms.py` | WebDAV/VOMS | WebDAV VOMS | Agnostic |
| `test_wire_protocol_security.py` | Protocol/Security | Wire security | Agnostic |
| `test_write.py` | I/O | Write ops | Agnostic |
| `test_write_recovery.py` | I/O/Recovery | Write recovery | Agnostic |
| `test_xrdcp_client_options.py` | Client | xrdcp options | Agnostic |
| `test_xrdcp_root_anon_compare.py` | Client | xrdcp anon compare | Agnostic |
| `test_xrdhttp_conformance.py` | HTTP | XRootD/HTTP conf | Agnostic |
| `test_xrdhttp.py` | HTTP | XRootD/HTTP | Agnostic |
| `test_xrootd_performance_conformance.py` | Protocol | Perf conformance | Agnostic |
| `test_xrootd.py` | Protocol | XRootD core | Agnostic |
| `tpc_parse_helpers.py` | TPC/Helpers | TPC parsing helpers | Agnostic |
| `upstream_protocol_stubs.py` | Infrastructure | Protocol stubs | Agnostic |
| `load_test.py` | Performance | Load testing | Nginx-Specific |
| `manage_test_servers.py` | Infrastructure | Test server management | Nginx-Specific |
| `settings.py` | Infrastructure | Test settings | Nginx-Specific |
| `test_a_webdav_clients.py` | WebDAV | WebDAV client compatibility | Nginx-Specific |
| `test_cache_write_through.py` | Cache | Write-through cache | Nginx-Specific |
| `test_crl.py` | Security/TLS | CRL validation | Nginx-Specific |
| `test_cross_protocol_access_logging.py` | Logging | Access logging | Nginx-Specific |
| `test_dashboard.py` | Metrics | Dashboard metrics | Nginx-Specific |
| `test_e2e_redirector_xrdcp.py` | Redirection | Redirector/xrdcp E2E | Nginx-Specific |
| `test_evil_actor.py` | Security/Adversarial | Worker-crash hunt over hostile XRootD wire frames + disconnect-mid-AIO ([guide](adversarial-testing.md)) | Nginx-Specific |
| `test_evil_actor_v2.py` | Security/Adversarial | Deeper race hunt: cross-connection bind handles + cross-protocol, LD_PRELOAD-deterministic ([guide](adversarial-testing.md)) | Nginx-Specific |
| `race_shim.c` | Security/Helper | LD_PRELOAD worker-gated syscall slower that makes worker-vs-event-loop races deterministic | Nginx-Specific |
| `test_gsi_bridge.py` | Security/GSI | GSI security bridge | Nginx-Specific |
| `test_http_cache_hit.py` | Cache | HTTP cache hits | Nginx-Specific |
| `test_http_webdav_lock.py` | WebDAV/Lock | WebDAV locking | Nginx-Specific |
| `test_http_webdav_lock_recursive.py` | WebDAV/Lock | Recursive locking | Nginx-Specific |
| `test_interop_query.py` | Protocol/Query | Query interoperability | Nginx-Specific |
| `test_manager_mode.py` | Cluster/Manager | Manager mode | Nginx-Specific |
| `test_metrics.py` | Metrics | General metrics | Nginx-Specific |
| `test_path_depth_guards.py` | Security/FS | Path depth guards | Nginx-Specific |
| `test_proxy_mode.py` | Proxy | Proxy mode | Nginx-Specific |
| `test_s3_metrics.py` | S3/Metrics | S3 metrics | Nginx-Specific |
| `test_s3_xrootd_gateway.py` | S3/Gateway | S3 XRootD gateway | Nginx-Specific |
| `test_vo_acl.py` | Security/ACL | VO ACLs | Nginx-Specific |
| `test_webdav_auth_cache.py` | WebDAV/Auth | WebDAV auth cache | Nginx-Specific |
| `test_webdav_http_security.py` | WebDAV/Security | WebDAV security | Nginx-Specific |
| `test_webdav_metrics.py` | Metrics | WebDAV metrics | Nginx-Specific |
| `test_webdav_spooled_put.py` | WebDAV | WebDAV spooled PUT | Nginx-Specific |
| `test_webdav_tpc_cred.py` | WebDAV/TPC | WebDAV TPC creds | Nginx-Specific |
| `test_wlcg_audit_log.py` | Logging | WLCG audit logs | Nginx-Specific |
| `test_xrdhttp_auth.py` | HTTP/Auth | XRootD/HTTP auth | Nginx-Specific |
| `test_xrdhttp_tpc.py` | HTTP/TPC | XRootD/HTTP TPC | Nginx-Specific |
| `test_xrdhttp_webdav.py` | HTTP/WebDAV | XRootD/HTTP WebDAV | Nginx-Specific |
