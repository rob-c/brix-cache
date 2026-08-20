"""Protocol/CMS stub procs, the CMS and hybrid meshes, the krb5 tier.

Split out of ``fleet_specs.py`` (TS-4 item 7).
"""

from __future__ import annotations

import os
import sys

import brix_suite.settings as S
from brix_suite.registry import NginxInstanceSpec

from brix_suite.catalogue._shared import (
    _TESTS_DIR, _data, _ded, _module_env, _nginx_has_krb5,
)

__all__ = ["support_specs"]


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
    # runs shutil.which() at import, kept out of module top-level.  Both mesh
    # orchestrators are started with `-m` (TS-5), so both carry `_module_env`:
    # `-m` puts the CURRENT directory on sys.path, not the script's, and the
    # meshes reach `server_launcher` and its shard loader in the flat tree.
    from brix_suite.mesh.hybrid_mesh_lib import PORTS as _HYBRID_PORTS
    from brix_suite.mesh.cms_mesh_lib import PORTS as _CMS_PORTS
    specs: list[NginxInstanceSpec] = [
        # Protocol stub backend for the stub-upstream-* proxies (binds a band in
        # the 131xx range; 13121 is a representative liveness anchor).
        NginxInstanceSpec(
            name="upstream-stubs", template="", port=S.STUB_WAIT_BACKEND_PORT,
            protocol="root", data_root=_data("data-upstream-stubs"),
            kind="proc", readiness="tcp",
            env={
                "TEST_STUB_REDIRECT_BACKEND_PORT": str(S.STUB_REDIRECT_BACKEND_PORT),
                "TEST_STUB_WAIT_BACKEND_PORT": str(S.STUB_WAIT_BACKEND_PORT),
                "TEST_STUB_WAITRESP_BACKEND_PORT": str(S.STUB_WAITRESP_BACKEND_PORT),
                "TEST_STUB_ERROR_BACKEND_PORT": str(S.STUB_ERROR_BACKEND_PORT),
                "TEST_STUB_AUTH_BACKEND_PORT": str(S.STUB_AUTH_BACKEND_PORT),
                "TEST_STUB_AUTH_NOFILE_BACKEND_PORT": str(S.STUB_AUTH_NOFILE_BACKEND_PORT),
                "TEST_STUB_GOTORLS_BACKEND_PORT": str(S.STUB_GOTORLS_BACKEND_PORT),
            },
            template_values={"argv": [py, os.path.join(_TESTS_DIR, "upstream_protocol_stubs.py")]},
            tags=("support",),
            reason="XRootD protocol stub backends (wait/redirect/authmore/gotoTLS).",
        ),
        # Hit-counting HTTP upstream for the phase-65 guard suites (mocks band).
        NginxInstanceSpec(
            name="guard-stub", template="", port=S.GUARD_STUB_PORT,
            protocol="http", data_root=_data("data-guard-stub"),
            kind="proc", readiness="tcp",
            env=_module_env(),
            template_values={"argv": [py, "-m", "brix_suite.servers.guard_stub_server"]},
            tags=("support", "mock"),
            reason="Hit-counting HTTP stub backend for the guard suites.",
        ),
        # Stateless ORIGIN-OK backend for admin-API URL validation (mocks band).
        NginxInstanceSpec(
            name="static-origin", template="", port=S.STATIC_ORIGIN_PORT,
            protocol="http", data_root=_data("data-static-origin"),
            kind="proc", readiness="tcp",
            env=_module_env(),
            template_values={"argv": [py, "-m", "brix_suite.servers.static_origin_server"]},
            tags=("support", "mock"),
            reason="Static HTTP origin backend for the dashboard admin-API suite.",
        ),
        # Hit-recording mirror shadow upstream for phase-24 (mocks band).
        NginxInstanceSpec(
            name="mirror-shadow", template="", port=S.MIRROR_SHADOW_PORT,
            protocol="http", data_root=_data("data-mirror-shadow"),
            kind="proc", readiness="tcp",
            env=_module_env(),
            template_values={"argv": [py, "-m", "brix_suite.servers.mirror_shadow_server"]},
            tags=("support", "mock"),
            reason="Hit-recording HTTP shadow upstream for the mirror suite.",
        ),
        # Mock RFC 7662 token-introspection IdP for phase-21 OIDC (mocks band).
        NginxInstanceSpec(
            name="introspect-idp", template="", port=S.INTROSPECT_IDP_PORT,
            protocol="http", data_root=_data("data-introspect-idp"),
            kind="proc", readiness="tcp",
            env=_module_env(),
            template_values={"argv": [py, "-m", "brix_suite.servers.introspect_idp_server"]},
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
            env=_module_env({"TEST_NGINX_BIN": S.NGINX_BIN,
                             "CMS_MESH_DIR": _data("cms-mesh")}),
            template_values={
                "start_argv": [py, "-m", "brix_suite.mesh.cms_mesh_servers", "start"],
                "stop_argv": [py, "-m", "brix_suite.mesh.cms_mesh_servers", "stop"],
            },
            tags=("support", "mesh"),
            reason="CMS cluster mesh (self-contained cmsd/brix/nginx topologies).",
        ),
        # Hybrid two-tier cross-backend mesh (own 11300-11317 band + /tmp tree).
        NginxInstanceSpec(
            name="hybrid-mesh", template="", port=_HYBRID_PORTS["a_data"],
            protocol="root", data_root=_data("hybrid-mesh"),
            kind="external", readiness="tcp", allow_remote_skip=True,
            env=_module_env({"TEST_NGINX_BIN": S.NGINX_BIN,
                             "HYBRID_MESH_DIR": _data("hybrid-mesh")}),
            template_values={
                "start_argv": [py, "-m", "brix_suite.mesh.hybrid_mesh_servers", "start"],
                "stop_argv": [py, "-m", "brix_suite.mesh.hybrid_mesh_servers", "stop"],
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
