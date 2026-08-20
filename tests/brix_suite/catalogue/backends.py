"""Stock-xrootd anonymous backends: the upstream and proxy targets.

Split out of ``fleet_specs.py`` (TS-4 item 7).
"""

from __future__ import annotations

import brix_suite.settings as S
from brix_suite.registry import NginxInstanceSpec

from brix_suite.catalogue._shared import _xrd_backend

__all__ = ["xrootd_backend_specs"]


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
