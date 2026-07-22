"""Declarative catalogue of the registry-native test fleet.

This is the pure-Python successor to the bash ``start_all_dedicated`` table in
``tests/lib/dedicated.sh`` + the reference-server launchers in
``tests/lib/{refxrootd,xrdhttp}.sh``.  Every fixed-role instance the old fleet
brought up becomes an :class:`NginxInstanceSpec` here, registered by
:func:`register_full_fleet` and launched by ``RegistryLauncher``.

Ports are pinned to the ``settings.py`` constants (not OS-assigned) so endpoints
stay byte-identical to the pre-migration fleet — the 414 test files that import
those fixed ports need no change.

The catalogue is built up stage by stage (see the plan in
``.claude/plans/steady-sniffing-galaxy.md``):

* **CORE** — main shared nginx, the reference xrootd servers, the XrdHttp
  gateway.  These are the instances ``start_all_dedicated`` brings up before the
  dedicated roles; the main nginx and the anonymous reference xrootd are tagged
  ``critical`` (a failure aborts start-all, as in bash).
* **DEDICATED / MESH / KRB5** — appended in later stages.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import settings as S
from server_registry import NginxInstanceSpec, register_nginx
from settings import (
    NGINX_ANON_PORT,
    PROXY_NGINX_PORT,
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    PROXY_BRIDGE_BRIX_PORT,
    ROOT_TPC_REF_PORT,
    TEST_ROOT,
    XRDHTTP_HTTP_PORT,
    XRDHTTP_ROOT_PORT,
)


def _data(name: str) -> str:
    return os.path.join(TEST_ROOT, name)


# fleet_prep-owned session artifact locations (created before instances start,
# mirroring the top of bash ``start_all_dedicated``): CRL drop dirs and the
# jwks-refresh signing directory.  Encoded here so the CRL/jwks-refresh specs can
# reference them; ``fleet_prep.prepare`` (stage 4) is what actually populates them.
_CRL_DIR = _data("crls")
_CRL_RELOAD_DIR = _data("crl-reload")
_JWKS_REFRESH_JSON = os.path.join(TEST_ROOT, "tokens", "jwks-refresh", "jwks.json")
_STAGE_HOOK = os.path.join(TEST_ROOT, "dedicated", "prepare-command", "stage_hook.py")


def core_specs() -> list[NginxInstanceSpec]:
    """The pre-dedicated core: main nginx + reference xrootd servers + XrdHttp."""
    shared_data = _data("data")
    return [
        # The canonical multi-listen nginx: every standard port (anon/gsi/token/
        # webdav/s3/metrics) lives in this one config, keyed off session values.
        # Readiness anchors on the anon root:// port. Critical: no suite without it.
        NginxInstanceSpec(
            name="main",
            template="nginx_shared.conf",
            port=NGINX_ANON_PORT,
            protocol="root",
            data_root=shared_data,
            readiness="root",
            tags=("core", "critical"),
            reason="Main shared nginx — all standard listen ports.",
        ),
        # Reference (stock) xrootd on the SHARED export, anonymous auth. Critical:
        # the differential-conformance suite compares our nginx against it.
        NginxInstanceSpec(
            name="ref-anon",
            template="xrootd_ref.conf",
            port=REF_BRIX_PORT,
            protocol="root",
            data_root=shared_data,
            kind="xrootd",
            readiness="root",
            tags=("core", "critical"),
            reason="Reference xrootd (anonymous) on the shared export.",
        ),
        # Reference xrootd with GSI. SECLIB/CA_DIR/SERVER_CERT/KEY come from the
        # session values + the launcher's generic SECLIB supply.
        NginxInstanceSpec(
            name="ref-gsi",
            template="xrootd_ref_gsi.conf",
            port=REF_BRIX_GSI_PORT,
            protocol="root",
            # Bash harness rooted the GSI reference at data-gsi-bridge (refxrootd.sh:
            # REF_BRIX_GSI_DATA_DIR=${TEST_ROOT}/data-gsi-bridge). test_gsi_bridge
            # writes its source files there and expects REF_BRIX_GSI_PORT to serve
            # them — keep the export path identical, not a fresh data-ref-gsi.
            data_root=_data("data-gsi-bridge"),
            kind="xrootd",
            readiness="root",
            tags=("core",),
            reason="Reference xrootd (GSI).",
        ),
        # GSI reference sharing the MAIN export (identity-mapping conformance).
        NginxInstanceSpec(
            name="ref-gsi-shared",
            template="xrootd_ref_gsi.conf",
            port=REF_BRIX_GSI_SHARED_PORT,
            protocol="root",
            data_root=shared_data,
            kind="xrootd",
            readiness="root",
            tags=("core",),
            reason="Reference xrootd (GSI) on the shared export.",
        ),
        # root:// TPC reference — drives third-party copies via xrdcp.
        NginxInstanceSpec(
            name="root-tpc-ref",
            template="xrootd_root_tpc.conf",
            port=ROOT_TPC_REF_PORT,
            protocol="root",
            data_root=_data("data-root-tpc-ref"),
            kind="xrootd",
            readiness="root",
            tags=("core",),
            template_values={"XRDCP_BIN": _xrdcp_bin()},
            reason="Reference xrootd for native root:// TPC.",
        ),
        # XrdPss proxy bridge — forwards to the proxy-mode nginx upstream.
        NginxInstanceSpec(
            name="pss-bridge",
            template="xrootd_pss_bridge.conf",
            port=PROXY_BRIDGE_BRIX_PORT,
            protocol="root",
            data_root=_data("data-pss-bridge"),
            kind="xrootd",
            readiness="root",
            env={"XRD_PARALLELEVTLOOP": "1", "XRD_WORKERTHREADS": "1"},
            template_values={"ORIGIN": f"localhost:{PROXY_NGINX_PORT}"},
            tags=("core",),
            reason="XrdPss reference bridge to the proxy-mode nginx.",
        ),
        # XrdHttp gateway (stock xrootd + XrdHttp module) — davs:// conformance.
        # HTTP_PORT is the readiness anchor; ROOT_PORT is the sibling root:// port.
        NginxInstanceSpec(
            name="xrdhttp",
            template="xrootd_xrdhttp.conf",
            port=XRDHTTP_HTTP_PORT,
            protocol="https",
            data_root=_data("data-xrdhttp"),
            kind="xrdhttp",
            readiness="tcp",
            extra_ports={"HTTP_PORT": XRDHTTP_HTTP_PORT, "ROOT_PORT": XRDHTTP_ROOT_PORT},
            tags=("core",),
            reason="Reference XrdHttp gateway (davs:// conformance).",
        ),
    ]


def _xrdcp_bin() -> str:
    import shutil

    return shutil.which(os.environ.get("XRDCP_BIN", "xrdcp")) or "xrdcp"


def _ded(
    name: str,
    template: str,
    port: int,
    *,
    env: dict[str, str] | None = None,
    requires: tuple[str, ...] = (),
    reason: str = "",
    host: str | None = None,
) -> NginxInstanceSpec:
    """A fixed-role nginx from bash ``start_dedicated_nginx``.

    ``data_root`` is ``$TEST_ROOT/data-<name>``; readiness is a bare TCP-listen
    probe (bash set ``SKIP_XRDFS_CHECK=1`` for every dedicated instance, so the
    fleet never blocked on an xrdfs handshake here).  Per-instance overrides
    (``CMS_PORT``, ``UPSTREAM_PORT``, ``NGINX_S3_PORT``, …) ride in ``env`` exactly
    as they did in the bash subshell — ``session_template_values`` reads them.
    """
    return NginxInstanceSpec(
        name=name,
        template=template,
        port=port,
        protocol="root",
        host=host,
        data_root=_data(f"data-{name}"),
        readiness="tcp",
        env=dict(env or {}),
        requires=requires,
        tags=("dedicated",),
        reason=reason or f"Dedicated nginx role: {name}.",
    )


def _xrd_backend(name: str, port: int, *, reason: str = "") -> NginxInstanceSpec:
    """A stock-xrootd anonymous backend from bash ``start_extra_ref_anon``.

    Renders the same committed ``xrootd_ref.conf`` template the core anon
    reference uses, on its own ``data-<name>`` export.  These are the real
    upstream backends the ``upstream-*`` / proxy nginx roles forward to.
    """
    return NginxInstanceSpec(
        name=name,
        template="xrootd_ref.conf",
        port=port,
        protocol="root",
        data_root=_data(f"data-{name}"),
        kind="xrootd",
        readiness="tcp",
        tags=("dedicated",),
        reason=reason or f"Reference xrootd backend: {name}.",
    )


def xrootd_backend_specs() -> list[NginxInstanceSpec]:
    """Real xrootd anon backends (upstream/proxy targets, interop-off)."""
    return [
        # Upstream migration backends — the real xrootd the upstream-* nginx
        # roles proxy to (ports 12120-12126). Named ``-be`` so the spec name
        # never collides with the same-labelled nginx proxy in front of it.
        _xrd_backend("upstream-redirect-be", S.UPSTREAM_REDIRECT_BACKEND_PORT),
        _xrd_backend("upstream-wait-be", S.UPSTREAM_WAIT_BACKEND_PORT),
        _xrd_backend("upstream-waitresp-be", S.UPSTREAM_WAITRESP_BACKEND_PORT),
        _xrd_backend("upstream-error-be", S.UPSTREAM_ERROR_BACKEND_PORT),
        _xrd_backend("upstream-auth-be", S.UPSTREAM_AUTH_BACKEND_PORT),
        _xrd_backend("upstream-auth-nofile-be", S.UPSTREAM_AUTH_NOFILE_BACKEND_PORT),
        _xrd_backend("upstream-gotorls-notls-be", S.UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT),
        # Differential-conformance "off" side: a stock xrootd on its own tree.
        _xrd_backend("interop-off", S.INTEROP_OFF_PORT),
        # Proxy-mode real upstream (test_proxy_mode.py scenario 1).
        _xrd_backend("proxy-upstream", S.PROXY_UPSTREAM_PORT),
    ]


_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _nginx_has_krb5() -> bool:
    """True iff the test nginx binary is linked against libkrb5.

    Mirrors bash ``start_krb5_tier``'s ``ldd $NGINX_BIN | grep libkrb5`` gate:
    when nginx was built without Kerberos, the whole krb5 tier is omitted so the
    fleet never tries to bring up a KDC + acceptor it cannot use.
    """
    if not os.path.exists(S.NGINX_BIN):
        return False
    # Probe the launcher's frozen copy, never the live build-tree binary: ldd
    # on objs/nginx caught mid-relink by a concurrent make reads a half-written
    # file, the gate flips False, and the krb5 specs silently vanish from the
    # registry (seen live as test_fleet_ports' unknown-spec-name failure).
    from server_launcher import _nginx_bin  # noqa: PLC0415 — lazy, avoids cycle
    try:
        out = subprocess.run(["ldd", _nginx_bin()], capture_output=True, text=True).stdout
    except OSError:
        return False
    return "libkrb5.so" in out


def support_specs() -> list[NginxInstanceSpec]:
    """Protocol/CMS stub procs, the CMS + hybrid meshes, and the krb5 tier.

    * ``proc`` stubs are long-lived Popen children with a known liveness port.
    * ``external`` orchestrators self-daemonize on ``start`` and tear down via
      ``stop`` (meshes) / ``down`` (KDC); the KDC's rc 3 is a clean skip.
    * The krb5 acceptor nginx is included only when nginx links libkrb5.
    """
    py = sys.executable or "python3"
    # Phase-5: the meshes are `external` orchestrators — start_argv blocks until
    # converged, so completion IS readiness and the primary port is never TCP-probed.
    # It is still pinned to each mesh's real front door (the source of truth in the
    # mesh libs) so `endpoint("...-mesh").port` is a stable fixed port, never the old
    # `endpoint_for` free_port fallback (now removed).  Local imports: cms_mesh_lib
    # runs shutil.which() at import, kept out of module top-level.
    from hybrid_mesh_lib import PORTS as _HYBRID_PORTS
    from cms_mesh_lib import PORTS as _CMS_PORTS
    specs: list[NginxInstanceSpec] = [
        # Protocol stub backend for the stub-upstream-* proxies (binds a band in
        # the 131xx range; 13121 is a representative liveness anchor).
        NginxInstanceSpec(
            name="upstream-stubs", template="", port=S.STUB_WAIT_BACKEND_PORT,
            protocol="root", data_root=_data("data-upstream-stubs"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "upstream_protocol_stubs.py")]},
            tags=("support",),
            reason="XRootD protocol stub backends (wait/redirect/authmore/gotoTLS).",
        ),
        # Hit-counting HTTP upstream for the phase-65 guard suites (mocks band).
        NginxInstanceSpec(
            name="guard-stub", template="", port=S.GUARD_STUB_PORT,
            protocol="http", data_root=_data("data-guard-stub"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "lib", "guard_stub_server.py")]},
            tags=("support", "mock"),
            reason="Hit-counting HTTP stub backend for the guard suites.",
        ),
        # Stateless ORIGIN-OK backend for admin-API URL validation (mocks band).
        NginxInstanceSpec(
            name="static-origin", template="", port=S.STATIC_ORIGIN_PORT,
            protocol="http", data_root=_data("data-static-origin"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "lib", "static_origin_server.py")]},
            tags=("support", "mock"),
            reason="Static HTTP origin backend for the dashboard admin-API suite.",
        ),
        # Hit-recording mirror shadow upstream for phase-24 (mocks band).
        NginxInstanceSpec(
            name="mirror-shadow", template="", port=S.MIRROR_SHADOW_PORT,
            protocol="http", data_root=_data("data-mirror-shadow"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "lib", "mirror_shadow_server.py")]},
            tags=("support", "mock"),
            reason="Hit-recording HTTP shadow upstream for the mirror suite.",
        ),
        # Mock RFC 7662 token-introspection IdP for phase-21 OIDC (mocks band).
        NginxInstanceSpec(
            name="introspect-idp", template="", port=S.INTROSPECT_IDP_PORT,
            protocol="http", data_root=_data("data-introspect-idp"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "lib", "introspect_idp_server.py")]},
            tags=("support", "mock"),
            reason="Mock OAuth token-introspection endpoint for the phase-21 suite.",
        ),
        # CMS parent-lookup stub for cluster-select/try/esc (binds 12601/12606/12607).
        NginxInstanceSpec(
            name="cms-parent-stubs", template="", port=S.CLUSTER_SELECT_CMS_PORT,
            protocol="root", data_root=_data("data-cms-parent-stubs"),
            kind="proc", readiness="tcp",
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "cms_parent_stubs.py")]},
            tags=("support",),
            reason="CMS parent stub (kYR_select / kYR_try) for parent-lookup clusters.",
        ),
        # CMS mesh: self-contained cmsd/brix/nginx topologies (own port band).
        NginxInstanceSpec(
            name="cms-mesh", template="", port=_CMS_PORTS["a_mgr"],
            protocol="root", data_root=_data("cms-mesh"),
            kind="external", readiness="tcp", allow_remote_skip=True,
            env={"TEST_NGINX_BIN": S.NGINX_BIN, "CMS_MESH_DIR": _data("cms-mesh")},
            template_values={
                "start_argv": [py, os.path.join(_TESTS_DIR, "cms_mesh_servers.py"), "start"],
                "stop_argv": [py, os.path.join(_TESTS_DIR, "cms_mesh_servers.py"), "stop"],
            },
            tags=("support", "mesh"),
            reason="CMS cluster mesh (self-contained cmsd/brix/nginx topologies).",
        ),
        # Hybrid two-tier cross-backend mesh (own 11300-11317 band + /tmp tree).
        NginxInstanceSpec(
            name="hybrid-mesh", template="", port=_HYBRID_PORTS["a_data"],
            protocol="root", data_root=_data("hybrid-mesh"),
            kind="external", readiness="tcp", allow_remote_skip=True,
            env={"TEST_NGINX_BIN": S.NGINX_BIN, "HYBRID_MESH_DIR": _data("hybrid-mesh")},
            template_values={
                "start_argv": [py, os.path.join(_TESTS_DIR, "hybrid_mesh_servers.py"), "start"],
                "stop_argv": [py, os.path.join(_TESTS_DIR, "hybrid_mesh_servers.py"), "stop"],
            },
            tags=("support", "mesh"),
            reason="Hybrid two-tier cross-backend mesh.",
        ),
    ]
    if _nginx_has_krb5():
        # The KDC provisions the realm + keytab; rc 3 = tooling absent (skip).
        specs.append(NginxInstanceSpec(
            name="krb5-kdc", template="", port=S.KRB5_KDC_PORT,
            protocol="root", data_root=_data("krb5"),
            kind="external", readiness="tcp",
            template_values={
                "start_argv": [py, os.path.join(_TESTS_DIR, "kdc_helpers.py"), "up"],
                "stop_argv": [py, os.path.join(_TESTS_DIR, "kdc_helpers.py"), "down"],
                "skip_returncodes": (3,),
            },
            tags=("support", "krb5"),
            reason="MIT KDC provisioning the test realm + keytab.",
        ))
        # The nginx GSSAPI acceptor; needs KRB5_CONFIG (realm + auth_to_local) in
        # its process environment plus the principal/keytab for substitution.
        krb5_dir = _data("krb5")
        specs.append(_ded(
            "krb5", "nginx_krb5.conf", S.NGINX_KRB5_PORT,
            env={
                "KRB5_CONFIG": os.path.join(krb5_dir, "krb5.conf"),
                "KRB5_PRINCIPAL": "xrootd/localhost@NGINX.TEST",
                "KRB5_KEYTAB": os.path.join(krb5_dir, "xrootd.keytab"),
            },
            requires=("krb5-kdc",),
            reason="nginx Kerberos (GSSAPI) acceptor.",
        ))
    return specs


def ha_specs() -> list[NginxInstanceSpec]:
    """HA cluster: two nginx instances on the SHARED export + an haproxy in front.

    Unlike the dedicated roles these serve the main ``$TEST_ROOT/data`` export
    (bash captured the global ``DATA_DIR`` before the subshell), so they are NOT
    tagged ``dedicated`` — no per-instance data tree, no export rehoming. haproxy
    is optional: it skips cleanly when the binary is absent (bash gated on
    ``have_cmd haproxy``).
    """
    shared_data = _data("data")
    ha1 = NginxInstanceSpec(
        name="ha-nginx1", template="nginx_ha_instance.conf", port=S.HA_NGINX1_PORT,
        protocol="root", data_root=shared_data, readiness="tcp", tags=("ha",),
        reason="HA cluster member 1 (shared export).",
    )
    ha2 = NginxInstanceSpec(
        name="ha-nginx2", template="nginx_ha_instance.conf", port=S.HA_NGINX2_PORT,
        protocol="root", data_root=shared_data, readiness="tcp", tags=("ha",),
        reason="HA cluster member 2 (shared export).",
    )
    haproxy = NginxInstanceSpec(
        name="ha-haproxy", template="haproxy.cfg", port=S.HA_HAPROXY_PORT,
        protocol="root", data_root=shared_data, kind="haproxy", readiness="tcp",
        requires=("ha-nginx1", "ha-nginx2"),
        template_values={
            "BIND_HOST": "127.0.0.1",
            "MAP_A_HOST": "127.0.0.1", "MAP_A_PORT": str(S.HA_NGINX1_PORT),
            "MAP_B_HOST": "127.0.0.1", "MAP_B_PORT": str(S.HA_NGINX2_PORT),
        },
        tags=("ha",),
        reason="HA failover front (haproxy over ha-nginx1/2).",
    )
    return [ha1, ha2, haproxy]


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
        # zip: one export over root:// + WebDAV + S3; the two HTTP ports are
        # hardcoded literals in test_zip_member.py (21198/21199), no settings const.
        _ded("zip", "nginx_zip.conf", 21196,
             env={"NGINX_HTTP_WEBDAV_PORT": "21198", "NGINX_S3_PORT": "21199"}),
        _ded("compress", "nginx_compress.conf", S.COMPRESS_WEBDAV_PORT,
             env={"NGINX_S3_PORT": str(S.COMPRESS_S3_PORT)}),
        _ded("interop-our", "nginx_interop.conf", S.INTEROP_OUR_PORT),
        # --- IPv6 roles (all listen on [::1]) ---------------------------------
        # The [::1] tier binds v6-only; the readiness probe must dial HOST6,
        # not settings.HOST, or every boot reports these as failed-to-start.
        _ded("ipv6-stream", "nginx_ipv6_stream.conf", S.IPV6_STREAM_PORT, host=S.HOST6),
        _ded("ipv6-mgr", "nginx_ipv6_mgr.conf", S.IPV6_MGR_PORT, host=S.HOST6),
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
        # nginx starts regardless of the stub being up; the stub proc is a
        # stage-4 spec the consuming tests depend on, not nginx startup.
        _ded("stub-upstream-redirect", "nginx_upstream_wait.conf", S.STUB_REDIRECT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_REDIRECT_BACKEND_PORT)}),
        _ded("stub-upstream-wait", "nginx_upstream_wait.conf", S.STUB_WAIT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_WAIT_BACKEND_PORT)}),
        _ded("stub-upstream-waitresp", "nginx_upstream_wait.conf", S.STUB_WAITRESP_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_WAITRESP_BACKEND_PORT)}),
        _ded("stub-upstream-error", "nginx_upstream_auth.conf", S.STUB_ERROR_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_ERROR_BACKEND_PORT)}),
        _ded("stub-upstream-auth", "nginx_stub_upstream_auth.conf", S.STUB_AUTH_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_AUTH_BACKEND_PORT)}),
        _ded("stub-upstream-auth-nofile", "nginx_upstream_wait.conf", S.STUB_AUTH_NOFILE_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_AUTH_NOFILE_BACKEND_PORT)}),
        _ded("stub-upstream-gotorls", "nginx_upstream_wait.conf", S.STUB_GOTORLS_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.STUB_GOTORLS_BACKEND_PORT)}),
        # real-upstream-redirect: proxy to a live XRootD redirector (cluster-redir).
        _ded("real-upstream-redirect", "nginx_upstream_wait.conf", S.REAL_REDIRECT_NGINX_PORT,
             env={"UPSTREAM_PORT": str(S.CLUSTER_REDIR_PORT)},
             requires=("cluster-redir",)),
        # --- TPC SSRF / S3 / security-level roles -----------------------------
        _ded("tpc-ssrf-default", "nginx_tpc_ssrf_default.conf", S.TPC_SSRF_DEFAULT_PORT),
        _ded("tpc-ssrf-allow-local", "nginx_tpc_ssrf_allow_local.conf", S.TPC_SSRF_ALLOW_LOCAL_PORT),
        _ded("tpc-ssrf-deny-private", "nginx_tpc_ssrf_deny_private.conf", S.TPC_SSRF_DENY_PRIVATE_PORT),
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
             env={"CMS_PORT": "11167", "CMS_PATHS": "/chaos-discovery"}),
        _ded("chaos-discovery-redir", "nginx_cluster_redir.conf", S.CHAOS_DISCOVERY_REDIR_PORT,
             env={"CMS_PORT": "11167"}, requires=("chaos-discovery-ds",)),
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
        _ded("cache-only", "nginx_cache_only.conf", S.CACHE_ONLY_PORT),
        _ded("wt-sync", "nginx_wt_sync.conf", S.WT_SYNC_PORT),
        _ded("wt-async", "nginx_wt_async.conf", S.WT_ASYNC_PORT),
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


def register_full_fleet() -> None:
    """Register every fixed-role fleet instance with the server registry.

    Idempotent: a name already present (e.g. re-entry within a session) is
    skipped rather than raising, so repeated calls are safe.
    """
    from server_registry import _SPECS  # noqa: PLC0415 — internal presence check

    for spec in _all_specs():
        if spec.name in _SPECS:
            continue
        register_nginx(spec)


def _all_specs() -> list[NginxInstanceSpec]:
    specs: list[NginxInstanceSpec] = []
    specs += core_specs()
    specs += xrootd_backend_specs()
    specs += support_specs()
    specs += dedicated_specs()
    specs += ha_specs()
    return specs
