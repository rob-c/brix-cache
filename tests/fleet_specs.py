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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "fleet_specs_part2.py")
