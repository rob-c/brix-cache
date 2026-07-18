"""Authoritative port-ownership map: every ``settings.py`` port constant → the
fleet spec that *listens* on it (or an explicit exemption).

Why this module exists
----------------------
Tests declare the servers they need with ``@pytest.mark.registry_server(<name>)``
markers, and the collection gate (``conftest._enforce_server_declarations``)
hard-fails any test that *uses* a fleet server it did not declare.  "Uses a
server" is detected statically from the ``settings.py`` port constants a test
references — so the gate needs to turn a constant (``NGINX_S3_PORT``) into the
owning spec (``main``).  That mapping cannot be inferred safely:

  * The main nginx is ONE instance listening on ~10 standard ports, but its spec
    only declares ``port=NGINX_ANON_PORT`` (the rest live in the template).
  * A dedicated spec's ``env`` carries BOTH owned secondary listens
    (``NGINX_S3_PORT`` on ``zip``/``compress``, ``CMS_PORT`` on a cluster
    manager) AND upstream *connections* to a DIFFERENT spec's port
    (``UPSTREAM_PORT``, ``META_CMS_PORT``) — which are NOT owned.
  * Some constants are not a server at all: synthetic data-server ports a test
    registers as raw CMS protocol payload, a deliberately-dead proxy upstream,
    or ports a single test's own fixture launches outside the fleet.

So ownership is stated explicitly here and kept honest by ``test_fleet_ports.py``
(completeness + consistency + no double-ownership).  The auto-derivable majority
(a spec's own ``port`` + ``extra_ports``) is computed; only the three cases above
are hand-authored.
"""

from __future__ import annotations

import settings as S
import fleet_specs


# --- hand-authored ownership ------------------------------------------------

# The main shared nginx serves every standard listen port from one config
# (nginx_shared.conf), keyed off the session values — so none but the anon port
# appear on the spec.  All belong to the ``main`` spec.
_MAIN_SHARED_CONSTS = (
    "NGINX_ANON_PORT",
    "NGINX_ANON_RESUME_OFF_PORT",
    "NGINX_GSI_PORT",
    "NGINX_GSI_TLS_PORT",
    "NGINX_TOKEN_PORT",
    "NGINX_METRICS_PORT",
    "NGINX_WEBDAV_PORT",
    "NGINX_WEBDAV_GSI_TLS_PORT",
    "NGINX_HTTP_WEBDAV_PORT",
    "NGINX_S3_PORT",
)

# Secondary listens owned by a dedicated spec but injected through its ``env``
# (a second listen of the same instance) or its template, so they are not the
# spec's primary ``port``.  Every entry here is cross-checked by the lint against
# the spec's env-injected owned-listen ports where one exists.
_SECONDARY_CONSTS = {
    # extra HTTP/S3 listens of a single multi-protocol export
    "READONLY_HTTP_S3_PORT": "readonly-http",
    "COMPRESS_S3_PORT": "compress",
    # CRL roles that also front a WebDAV / reload-stub listen
    "WEBDAV_CRL_PORT": "crl",
    "WEBDAV_DIR_PORT": "crl-dir",
    "CRL_RELOAD_HTTP_PORT": "crl-reload",
    # webdav-auth-cache serves a second (auth) listen from the same instance
    "WEBDAV_AUTH_CACHE_NGINX_PORT": "webdav-auth-cache",
    # cluster CMS (cmsd manager) listens — owned by the redirector/manager the
    # data-servers subscribe UP to (the DS specs merely connect to the same port)
    "CLUSTER_CMS_PORT": "cluster-redir",
    "CLUSTER_MP_CMS_PORT": "cluster-mp-redir",
    "CLUSTER_MS_CMS_PORT": "cluster-ms-redir",
    "CLUSTER_MW_CMS_PORT": "cluster-mw-mgr",
    "CLUSTER_3T_META_CMS_PORT": "cluster-3t-meta",
    "CLUSTER_3T_SUB_CMS_PORT": "cluster-3t-sub",
    "CLUSTER_3T_SELF_PORT": "cluster-3t-sub",
    "CLUSTER_SLOTS_CMS_PORT": "cluster-slots-redir",
    "CLUSTER_SLOTS_METRICS_PORT": "cluster-slots-redir",
    # escalation/try redirectors run their OWN cmsd manager listen (the value
    # is theirs, not the parent stub's port — cf. cluster-select, whose CMS_PORT
    # equals the cms-parent-stubs port and is therefore a connect, not owned)
    "CLUSTER_ESC_CMS_PORT": "cluster-esc-sub",
    "CLUSTER_TRY_CMS_PORT": "cluster-try",
    "CMS_TEST_CMS_PORT": "cms-test-mgr",
    # IPv6 manager's CMS + HTTP listens (template-driven, one instance)
    "IPV6_MGR_CMS_PORT": "ipv6-mgr",
    "IPV6_MGR_HTTP_PORT": "ipv6-mgr",
    # the upstream_protocol_stubs.py proc answers on every backend port
    "STUB_REDIRECT_BACKEND_PORT": "upstream-stubs",
    "STUB_WAITRESP_BACKEND_PORT": "upstream-stubs",
    "STUB_ERROR_BACKEND_PORT": "upstream-stubs",
    "STUB_AUTH_BACKEND_PORT": "upstream-stubs",
    "STUB_AUTH_NOFILE_BACKEND_PORT": "upstream-stubs",
    "STUB_GOTORLS_BACKEND_PORT": "upstream-stubs",
}

# Port constants that name NO fleet server: synthetic ports used only as protocol
# payload, deliberately-dead upstreams, unused legacy constants, or servers a
# single test's own fixture launches outside the session fleet.  A test may
# reference these freely without declaring a spec.
EXEMPT_PORTS = {
    "CLUSTER_GONE_DS_PORT": "synthetic DS port registered as raw CMS payload; nothing listens",
    "CLUSTER_GONE_DS_PORT_A": "synthetic DS port registered as raw CMS payload; nothing listens",
    "CLUSTER_GONE_DS_PORT_B": "synthetic DS port registered as raw CMS payload; nothing listens",
    "CLUSTER_SELECT_REDIRECT_PORT": "synthetic redirect target in a CMS-registered payload",
    "CLUSTER_TRY_FIRST_PORT": "synthetic DS port in a CMS-registered payload",
    "CLUSTER_TRY_SECOND_PORT": "synthetic DS port in a CMS-registered payload",
    "PROXY_DEAD_UPSTREAM_PORT": "deliberately-dead upstream (proxy-dead connects; no server binds)",
    "UPSTREAM_WAIT_NGINX_PORT": "unused legacy constant; no fleet spec claims it",
    "WEBDAV_TPC_SOURCE_OPEN_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
    "WEBDAV_TPC_DEST_CAFILE_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
    "WEBDAV_TPC_DEST_CADIR_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
    "WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
    "WEBDAV_TPC_DEST_DISABLED_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
    "WEBDAV_TPC_DEST_READONLY_PORT": "launched by test_webdav_tpc's tpc_nginx fixture, not the fleet",
}


# ``env`` keys whose port value is a secondary LISTEN of the same spec (owned),
# as opposed to a connection to another spec's port.  Used by the lint to
# cross-check _SECONDARY_CONSTS and by the collision map to widen ownership.
OWNED_LISTEN_ENV = frozenset({
    "NGINX_S3_PORT",
    "NGINX_HTTP_WEBDAV_PORT",
    "NGINX_WEBDAV_PORT",
    "NGINX_METRICS_PORT",
    "HTTP_STUB_PORT",
    "SELF_REGISTER_PORT",
    "CMS_PORT",
})

# ``env`` keys that reference a DIFFERENT spec's port (a connection, never owned).
CONNECT_ENV = frozenset({"UPSTREAM_PORT", "META_CMS_PORT"})


def _port_constants() -> dict[str, int]:
    """Every ``settings.py`` upper-case int constant in the TCP port range."""
    return {
        n: getattr(S, n)
        for n in dir(S)
        if n.isupper()
        and isinstance(getattr(S, n), int)
        and 1024 <= getattr(S, n) <= 65535
    }


def _primary_const_by_spec() -> dict[str, str]:
    """Constant-name → spec-name for each spec's own ``port`` and ``extra_ports``.

    A port value may be named by several settings constants (aliases); every
    such alias maps to the owning spec.
    """
    value_to_const: dict[int, list[str]] = {}
    for name, value in _port_constants().items():
        value_to_const.setdefault(value, []).append(name)

    mapping: dict[str, str] = {}
    for spec in fleet_specs._all_specs():
        owned = set()
        if spec.port is not None:
            owned.add(spec.port)
        owned.update(v for v in spec.extra_ports.values() if v is not None)
        for value in owned:
            for const in value_to_const.get(value, ()):
                mapping[const] = spec.name
    return mapping


def const_to_spec() -> dict[str, str]:
    """The full, authoritative constant-name → owning-spec map.

    Union of the auto-derived primary/extra ports, the main shared listens, and
    the hand-authored secondary listens.  Exempt constants are absent by design.
    """
    mapping = _primary_const_by_spec()
    mapping.update({c: "main" for c in _MAIN_SHARED_CONSTS})
    mapping.update(_SECONDARY_CONSTS)
    return mapping


#: Module-level cached view for import-time consumers (conftest gate, lint).
CONST_TO_SPEC = const_to_spec()
