"""The fixed-role dedicated nginx instances.

The pure-Python successor to bash ``start_all_dedicated``'s table.
Split out of ``fleet_specs_part2.py`` (TS-4 item 7).
"""

from __future__ import annotations

import brix_suite.settings as S
from brix_suite.registry import NginxInstanceSpec

from brix_suite.catalogue._shared import (
    _CRL_DIR,
    _CRL_RELOAD_DIR,
    _JWKS_REFRESH_JSON,
    _STAGE_HOOK,
    _ded,
)

__all__ = ["dedicated_specs"]


def dedicated_specs() -> list[NginxInstanceSpec]:
    """The ~90 fixed-role nginx instances from bash ``start_all_dedicated``.

    A near-mechanical transcription of the ``start_dedicated_nginx`` table, in
    the same order bash brought them up, with the per-instance env overrides its
    subshell exported.  ``requires`` encodes the ordering bash relied on
    (redirector before data-server, cache tier before proxy tier, backend before
    the proxy in front of it) so ``dependency_order`` sequences them faithfully.
    """
    return [
        # --- ACL / token roles ------------------------------------------------
        _ded("readonly", "nginx_readonly.conf", S.READONLY_PORT),
        _ded("vo-acl", "nginx_vo_acl.conf", S.VO_PORT),
        # The manager map front-ends the reference xrootd pair: MAP_A defaults to
        # ref-anon (REF_PORT) and MAP_B to ref-gsi (REF_PORT+1) via
        # fleet_values.  Those backends used to be always-on backbone; with the
        # zero-boot default they must be pulled in explicitly, so the dependency
        # is declared here (dependency_closure then boots them for any manager test).
        _ded("manager", "nginx_manager.conf", S.MANAGER_PORT,
             requires=("ref-anon", "ref-gsi")),
        _ded("token-strict", "nginx_token_strict.conf", S.NGINX_TOKEN_STRICT_PORT),
        _ded("token-multikey", "nginx_token_multikey.conf", S.NGINX_TOKEN_MULTIKEY_PORT),
        _ded("token-registry", "nginx_token_registry.conf", S.NGINX_TOKEN_REGISTRY_PORT),
        _ded("webdav-token", "nginx_webdav_token.conf", S.NGINX_WEBDAV_TOKEN_PORT),
        # --- migrated self-provisioning fixtures ------------------------------
        _ded("open-flags-lifecycle", "nginx_tpc_ssrf_default.conf", S.OPEN_FLAGS_LIFECYCLE_NGINX_PORT),
        _ded("webdav-dellock", "nginx_webdav-dellock.conf", S.WEBDAV_DELLOCK_PORT),
        _ded("webdav-unlock-ownership", "nginx_webdav-unlock-ownership.conf", S.WEBDAV_UNLOCK_OWNERSHIP_PORT),
        _ded("s3-mpu", "nginx_s3-mpu.conf", S.S3_MPU_PORT),
        _ded("readonly-http", "nginx_readonly-http.conf", S.READONLY_HTTP_DAV_PORT,
             env={"NGINX_S3_PORT": str(S.READONLY_HTTP_S3_PORT)}),
        _ded("xrdhttp-digest", "nginx_xrdhttp_digest.conf", S.XRDHTTP_DIGEST_PORT),
        # zip: one export over root:// + WebDAV + S3.
        _ded("zip", "nginx_zip.conf", S.ZIP_ROOT_PORT,
             env={"NGINX_HTTP_WEBDAV_PORT": str(S.ZIP_WEBDAV_PORT),
                  "NGINX_S3_PORT": str(S.ZIP_S3_PORT)}),
        _ded("compress", "nginx_compress.conf", S.COMPRESS_WEBDAV_PORT,
             env={"NGINX_S3_PORT": str(S.COMPRESS_S3_PORT)}),
        _ded("interop-our", "nginx_interop.conf", S.INTEROP_OUR_PORT),
        # --- IPv6 roles (all listen on [::1]) ---------------------------------
        # The [::1] tier binds v6-only; the readiness probe must dial HOST6,
        # not settings.HOST, or every boot reports these as failed-to-start.
        _ded("ipv6-stream", "nginx_ipv6_stream.conf", S.IPV6_STREAM_PORT, host=S.HOST6),
        _ded("ipv6-mgr", "nginx_ipv6_mgr.conf", S.IPV6_MGR_PORT, host=S.HOST6,
             env={"CMS_PORT": str(S.IPV6_MGR_CMS_PORT),
                  "NGINX_METRICS_PORT": str(S.IPV6_MGR_HTTP_PORT)}),
        _ded("ipv6-webdav", "nginx_ipv6_webdav.conf", S.IPV6_WEBDAV_PORT, host=S.HOST6),
        _ded("ipv6-s3", "nginx_ipv6_s3.conf", S.IPV6_S3_PORT, host=S.HOST6),
        _ded("ipv6-upstream", "nginx_ipv6_upstream.conf", S.IPV6_UPSTREAM_PORT, host=S.HOST6),
        _ded("ipv6-proxy", "nginx_ipv6_proxy.conf", S.IPV6_PROXY_PORT, host=S.HOST6),
        # --- CRL roles --------------------------------------------------------
        _ded("crl", "nginx_crl.conf", S.CRL_PORT,
             env={"NGINX_WEBDAV_PORT": str(S.WEBDAV_CRL_PORT)}),
        _ded("crl-dir", "nginx_crl.conf", S.CRL_DIR_PORT,
             env={"CRL_PATH": _CRL_DIR, "NGINX_WEBDAV_PORT": str(S.WEBDAV_DIR_PORT)}),
        _ded("crl-reload", "nginx_crl_reload.conf", S.CRL_RELOAD_PORT,
             env={"CRL_PATH": _CRL_RELOAD_DIR, "CRL_RELOAD_INTERVAL": "2",
                  "HTTP_STUB_PORT": str(S.CRL_RELOAD_HTTP_PORT)}),
        # --- WebDAV / TPC roles ----------------------------------------------
        _ded("webdav-auth-cache", "nginx_webdav_auth_cache.conf", S.WEBDAV_AUTH_CACHE_MANUAL_PORT),
        _ded("webdav-tpc", "nginx_webdav_tpc.conf", S.WEBDAV_TPC_SOURCE_REQUIRED_PORT),
        _ded("root-tpc", "nginx_root_tpc.conf", S.ROOT_TPC_NGINX_PORT),
        _ded("jwks-refresh", "nginx_jwks_refresh.conf", S.NGINX_JWKS_REFRESH_PORT,
             env={"JWKS_FILE": _JWKS_REFRESH_JSON, "REFRESH_INTERVAL_MS": "500",
                  "TOKEN_ISSUER": "https://test.example.com", "TOKEN_AUDIENCE": "nginx-xrootd"}),
        # --- upstream-* proxies (front the real xrootd -be backends) ----------
        _ded("upstream-redirect", "nginx_upstream_wait.conf", S.UPSTREAM_REDIRECT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_REDIRECT_BACKEND_PORT)},
             requires=("upstream-redirect-be",)),
        _ded("upstream-waitresp", "nginx_upstream_wait.conf", S.UPSTREAM_WAITRESP_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_WAITRESP_BACKEND_PORT)},
             requires=("upstream-waitresp-be",)),
        _ded("upstream-error", "nginx_upstream_auth.conf", S.UPSTREAM_ERROR_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_ERROR_BACKEND_PORT)},
             requires=("upstream-error-be",)),
        _ded("upstream-auth", "nginx_upstream_auth.conf", S.UPSTREAM_AUTH_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_AUTH_BACKEND_PORT)},
             requires=("upstream-auth-be",)),
        _ded("upstream-auth-nofile", "nginx_upstream_wait.conf", S.UPSTREAM_AUTH_NOFILE_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_AUTH_NOFILE_BACKEND_PORT)},
             requires=("upstream-auth-nofile-be",)),
        _ded("upstream-gotorls-notls", "nginx_upstream_wait.conf", S.UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT)},
             requires=("upstream-gotorls-notls-be",)),
        # --- stub-backed upstream proxies (proxy to upstream_protocol_stubs.py) --
        # nginx starts regardless of the stub being up, but the *test* is
        # meaningless without it: a front with a dead upstream answers every
        # locate with kXR_error, which silently masquerades as "the proxy
        # forwarded an error".  Under the zero-boot gate a `registry_server`
        # marker boots only the dependency closure, so each front must name the
        # stub proc explicitly or it runs against nothing (2026-08-05).

        _ded("stub-upstream-redirect", "nginx_upstream_wait.conf", S.STUB_REDIRECT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_REDIRECT_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-wait", "nginx_upstream_wait.conf", S.STUB_WAIT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_WAIT_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-waitresp", "nginx_upstream_wait.conf", S.STUB_WAITRESP_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_WAITRESP_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-error", "nginx_upstream_auth.conf", S.STUB_ERROR_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_ERROR_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-auth", "nginx_stub_upstream_auth.conf", S.STUB_AUTH_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_AUTH_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-auth-nofile", "nginx_upstream_wait.conf", S.STUB_AUTH_NOFILE_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_AUTH_NOFILE_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        _ded("stub-upstream-gotorls", "nginx_upstream_wait.conf", S.STUB_GOTORLS_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_GOTORLS_BACKEND_PORT)},
             requires=("upstream-stubs",)),
        # real-upstream-redirect: proxy to a live XRootD redirector (cluster-redir).
        _ded("real-upstream-redirect", "nginx_upstream_wait.conf", S.REAL_REDIRECT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.CLUSTER_REDIR_PORT)},
             requires=("cluster-redir",)),
        # --- TPC SSRF / S3 / security-level roles -----------------------------
        _ded("tpc-ssrf-default", "nginx_tpc_ssrf_default.conf", S.TPC_SSRF_DEFAULT_PORT),
        _ded("tpc-ssrf-allow-local", "nginx_tpc_ssrf_allow_local.conf", S.TPC_SSRF_ALLOW_LOCAL_PORT),
        _ded("tpc-ssrf-deny-private", "nginx_tpc_ssrf_deny_private.conf", S.TPC_SSRF_DENY_PRIVATE_PORT),
        _ded("tpc-source-guard", "nginx_tpc_source_guard.conf", S.TPC_SRC_GUARD_PORT),
        _ded("webdav-tpc-source-guard", "nginx_webdav_tpc_source_guard.conf", S.WEBDAV_TPC_SRC_GUARD_PORT),
        _ded("s3-presigned", "nginx_s3_presigned.conf", S.S3_PRESIGNED_PORT),
        _ded("s3-presigned-sts", "nginx_s3_presigned_sts.conf", S.S3_PRESIGNED_STS_PORT),
        _ded("s3-token", "nginx_s3_token.conf", S.NGINX_S3_TOKEN_PORT),
        _ded("security-level-standard", "nginx_security_level_standard.conf", S.SECURITY_LEVEL_STANDARD_PORT),
        _ded("security-level-pedantic", "nginx_security_level_pedantic.conf", S.SECURITY_LEVEL_PEDANTIC_PORT),
        # --- CMS single cluster (redir before ds) -----------------------------
        _ded("cluster-redir", "nginx_cluster_redir.conf", S.CLUSTER_REDIR_PORT,
             env={"CMS_PORT": str(S.CLUSTER_CMS_PORT)}),
        _ded("cluster-ds", "nginx_cluster_ds.conf", S.CLUSTER_DS_PORT,
             env={"CMS_PORT": str(S.CLUSTER_CMS_PORT), "CMS_PATHS": "/"},
             requires=("cluster-redir",)),
        _ded("http-cache", "nginx_http_cache.conf", S.NGINX_HTTP_CACHE_PORT),
        _ded("webdav-voms", "nginx_webdav_voms.conf", S.NGINX_WEBDAV_VOMS_PORT),
        # --- CMS heartbeat pair -----------------------------------------------
        _ded("cms-test-mgr", "nginx_cluster_redir.conf", S.CMS_TEST_REDIR_PORT,
             env={"CMS_PORT": str(S.CMS_TEST_CMS_PORT)}),
        _ded("cms-test", "nginx_cms_test.conf", S.CMS_TEST_NGINX_PORT,
             env={"CMS_PORT": str(S.CMS_TEST_CMS_PORT)},
             requires=("cms-test-mgr",)),
        # --- Chaos Mesh tier stack (storage <- cache <- proxy) ----------------
        _ded("chaos-tier3", "nginx_chaos_tier3_storage.conf", S.CHAOS_TIER3_PORT),
        _ded("chaos-tier2", "nginx_chaos_tier2_cache.conf", S.CHAOS_TIER2_PORT,
             env={"UPSTREAM_PORT": str(S.CHAOS_TIER3_PORT)}, requires=("chaos-tier3",)),
        _ded("chaos-tier1", "nginx_proxy_mode.conf", S.CHAOS_TIER1_PORT,
             env={"UPSTREAM_PORT": str(S.CHAOS_TIER2_PORT)}, requires=("chaos-tier2",)),
        # Chaos discovery: DS FIRST (registers once its late manager appears), so
        # the delayed-start test sees the failed-then-successful CMS login.
        _ded("chaos-discovery-ds", "nginx_cluster_ds.conf", S.CHAOS_DISCOVERY_DS_PORT,
             env={"CMS_PORT": str(S.CHAOS_DISCOVERY_CMS_PORT),
                  "CMS_PATHS": "/chaos-discovery"}),
        _ded("chaos-discovery-redir", "nginx_cluster_redir.conf", S.CHAOS_DISCOVERY_REDIR_PORT,
             env={"CMS_PORT": str(S.CHAOS_DISCOVERY_CMS_PORT)},
             requires=("chaos-discovery-ds",)),
        # --- proxy-mode pairs -------------------------------------------------
        _ded("proxy-nginx", "nginx_proxy_mode.conf", S.PROXY_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.PROXY_UPSTREAM_PORT)}, requires=("proxy-upstream",)),
        _ded("proxy-dead", "nginx_proxy_mode.conf", S.PROXY_DEAD_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.PROXY_DEAD_UPSTREAM_PORT)}),
        _ded("pure-nginx-proxy", "nginx_proxy_mode.conf", S.PROXY_PURE_NGINX_PROXY_PORT,
             env={"UPSTREAM_PORT": str(S.PROXY_NGINX_PORT)}, requires=("proxy-nginx",)),
        _ded("credential-bridge", "nginx_credential_bridge.conf", S.CREDENTIAL_BRIDGE_PORT,
             env={"UPSTREAM_PORT": str(S.NGINX_TOKEN_PORT)}),
        _ded("authdb", "nginx_authdb.conf", S.AUTHDB_PORT),
        # --- multi-path cluster -----------------------------------------------
        _ded("cluster-mp-redir", "nginx_cluster_redir.conf", S.CLUSTER_MP_REDIR_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MP_CMS_PORT)}),
        _ded("cluster-mp-ds", "nginx_cluster_ds_multipath.conf", S.CLUSTER_MP_DS_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MP_CMS_PORT)}, requires=("cluster-mp-redir",)),
        # --- multi-server cluster ---------------------------------------------
        _ded("cluster-ms-redir", "nginx_cluster_redir.conf", S.CLUSTER_MS_REDIR_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MS_CMS_PORT)}),
        _ded("cluster-ms-ds1", "nginx_cluster_ds.conf", S.CLUSTER_MS_DS1_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-ms-redir",)),
        _ded("cluster-ms-ds2", "nginx_cluster_ds.conf", S.CLUSTER_MS_DS2_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-ms-redir",)),
        # --- multi-worker cluster ---------------------------------------------
        _ded("cluster-mw-mgr", "nginx_cluster_redir.conf", S.CLUSTER_MW_REDIR_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MW_CMS_PORT)}),
        _ded("cluster-mw", "nginx_cluster_multi_worker.conf", S.CLUSTER_MW_PORT,
             env={"CMS_PORT": str(S.CLUSTER_MW_CMS_PORT)}, requires=("cluster-mw-mgr",)),
        # --- three-tier topology (meta -> sub -> leaf) ------------------------
        _ded("cluster-3t-meta", "nginx_cluster_redir.conf", S.CLUSTER_3T_META_PORT,
             env={"CMS_PORT": str(S.CLUSTER_3T_META_CMS_PORT)}),
        _ded("cluster-3t-sub", "nginx_cluster_sub_manager.conf", S.CLUSTER_3T_SUB_PORT,
             env={"CMS_PORT": str(S.CLUSTER_3T_SUB_CMS_PORT),
                  "META_CMS_PORT": str(S.CLUSTER_3T_META_CMS_PORT),
                  "SELF_REGISTER_PORT": str(S.CLUSTER_3T_SELF_PORT)},
             requires=("cluster-3t-meta",)),
        _ded("cluster-3t-leaf", "nginx_cluster_ds.conf", S.CLUSTER_3T_LEAF_PORT,
             env={"CMS_PORT": str(S.CLUSTER_3T_SUB_CMS_PORT), "CMS_PATHS": "/"},
             requires=("cluster-3t-sub",)),
        # --- CMS parent-lookup roles (query cms_parent_stubs.py, a stage-4 proc) --
        _ded("cluster-select", "nginx_cluster_parent_lookup.conf", S.CLUSTER_SELECT_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SELECT_CMS_PORT), "CMS_PATHS": "/"},
             requires=("cms-parent-stubs",)),
        # --- full-registry (slots) cluster ------------------------------------
        _ded("cluster-slots-redir", "nginx_cluster_slots_redir.conf", S.CLUSTER_SLOTS_REDIR_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SLOTS_CMS_PORT),
                  "NGINX_METRICS_PORT": str(S.CLUSTER_SLOTS_METRICS_PORT)}),
        _ded("cluster-slots-ds1", "nginx_cluster_ds.conf", S.CLUSTER_SLOTS_DS1_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SLOTS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-slots-redir",)),
        _ded("cluster-slots-ds2", "nginx_cluster_ds.conf", S.CLUSTER_SLOTS_DS2_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SLOTS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-slots-redir",)),
        _ded("cluster-slots-ds3", "nginx_cluster_ds.conf", S.CLUSTER_SLOTS_DS3_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SLOTS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-slots-redir",)),
        _ded("cluster-slots-ds4", "nginx_cluster_ds.conf", S.CLUSTER_SLOTS_DS4_PORT,
             env={"CMS_PORT": str(S.CLUSTER_SLOTS_CMS_PORT), "CMS_PATHS": "/"}, requires=("cluster-slots-redir",)),
        _ded("cluster-try", "nginx_cluster_parent_lookup.conf", S.CLUSTER_TRY_PORT,
             env={"CMS_PORT": str(S.CLUSTER_TRY_CMS_PORT), "CMS_PATHS": "/"},
             requires=("cms-parent-stubs",)),
        _ded("cluster-esc-sub", "nginx_cluster_parent_lookup.conf", S.CLUSTER_ESC_SUB_PORT,
             env={"CMS_PORT": str(S.CLUSTER_ESC_CMS_PORT), "CMS_PATHS": "/"},
             requires=("cms-parent-stubs",)),
        _ded("cluster-esc-leaf", "nginx_cluster_leaf.conf", S.CLUSTER_ESC_LEAF_PORT),
        # --- cache / write-through --------------------------------------------
        _ded("cache-only", "nginx_cache_only.conf", S.CACHE_ONLY_PORT,
             requires=("main",)),
        _ded("wt-sync", "nginx_wt_sync.conf", S.WT_SYNC_PORT,
             requires=("main",)),
        _ded("wt-async", "nginx_wt_async.conf", S.WT_ASYNC_PORT,
             requires=("main",)),
        # --- kXR_prepare staging pair -----------------------------------------
        _ded("prepare-command", "nginx_prepare_command.conf", S.PREPARE_CMD_PORT,
             env={"STAGE_CMD": _STAGE_HOOK}),
        _ded("prepare-nocmd", "nginx_prepare_staging.conf", S.PREPARE_NOCMD_PORT),
        # --- misc single roles ------------------------------------------------
        _ded("meta-only", "nginx_meta_only.conf", S.META_ONLY_PORT),
        _ded("supervisor", "nginx_supervisor.conf", S.SUPERVISOR_PORT),
        _ded("virtual-redir", "nginx_virtual_redir.conf", S.VIRTUAL_REDIR_PORT,
             env={"UPSTREAM_PORT": str(S.NGINX_ANON_PORT)}),
        _ded("collapse-redir", "nginx_collapse_redir.conf", S.COLLAPSE_REDIR_PORT,
             env={"UPSTREAM_PORT": str(S.NGINX_ANON_PORT)}),
    ]
