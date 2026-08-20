"""
Regression: a lone manager/redirector answers kXR_open with kXR_noserver, not EBADF.

A pure redirector (`brix_manager_mode on`, no `brix_storage_backend`/export) never
opens a local export root, so `conf->rootfd` stays -1.  When such a node has ZERO
registered data servers, no CMS parent, and no static map match, an open used to
fall through to `brix_open_resolved_file`, which did `openat(-1, ...)` and surfaced
a confusing raw EBADF -> kXR_IOError (3007).  `brix_open_manager_redirect` now
short-circuits that dead end with the honest kXR_noserver (3014) — "no data server
available" — the correct signal that the cluster has nowhere to land the request.

Cases (success + error + security-neg, per the change contract):
  * error   — a read AND a write open on an empty redirector return 3014,
              never the old 3007 (and never a silent hang / connection drop).
  * success — a static-map redirector (also rootfd == -1) that HAS a redirect
              target still redirects (4004): the new guard, scoped to
              `manager_mode && rootfd < 0`, fires only when there is genuinely
              nowhere to send the open, never on a redirector that can redirect.
  * neg     — a path-traversal open on the empty redirector is rejected at path
              validation (kXR_ArgInvalid) and NEVER surfaces a local-open EBADF:
              the redirector has no export and must never touch a filesystem.

Subset-boot note: these classes declare disjoint server sets that never register
with each other, so cluster-redir stays empty even though virtual-redir is also
booted for the session — the two redirectors are independent nginx instances.
"""
import socket
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, VIRTUAL_REDIR_PORT
from _test_a_robustness_helpers import (
    _errcode,
    _full_anon_login,
    _recv_response,
    make_open_req,
)

pytestmark = [pytest.mark.uses_lifecycle_harness, pytest.mark.timeout(60)]

EMPTY_REDIRECTOR = "lc-redirector-no-server"

# --- wire constants -------------------------------------------------------- #
kXR_ok         = 0
kXR_error      = 4003
kXR_redirect   = 4004
kXR_ArgInvalid = 3000
kXR_IOError    = 3007
kXR_noserver   = 3014

kXR_open_read  = 0x0010                 # kXR_open_read
kXR_open_write = 0x0020 | 0x0008        # kXR_open_updt | kXR_new (create-new)

_CONN_TIMEOUT = 3.0
_RECV_TIMEOUT = 10.0


def _connect(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(_CONN_TIMEOUT)
    s.connect((host, port))
    s.settimeout(_RECV_TIMEOUT)
    return s


def _wait_reachable(port: int, label: str, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _connect(HOST, port).close()
            return
        except OSError:
            time.sleep(0.1)
    pytest.skip(f"{label} not reachable on port {port}")


def _open_probe(port: int, path: str, options: int) -> tuple[int, int]:
    """Full bootstrap + one kXR_open against `port`; return (status, errcode).

    errcode is the kXR error code from a kXR_error body, else 0.
    """
    s = _connect(HOST, port)
    try:
        _, _, lg = _full_anon_login(s)
        assert lg == kXR_ok, f"anon login failed: {lg}"
        s.sendall(make_open_req(path.encode(), options))
        status, body = _recv_response(s)
        return status, (_errcode(body) if status == kXR_error else 0)
    finally:
        s.close()


class TestLoneRedirectorNoServer:
    """A private redirector with zero data servers registered."""

    @pytest.fixture
    def empty_redirector(self, lifecycle):
        return lifecycle.start(NginxInstanceSpec(
            name=EMPTY_REDIRECTOR,
            template="nginx_cluster_redir_nocms.conf",
            protocol="root",
            readiness="tcp",
            reason="redirector no-server regression (private empty registry)",
        ))

    def test_read_open_returns_noserver_not_ebadf(self, empty_redirector):
        _wait_reachable(empty_redirector.port, EMPTY_REDIRECTOR)
        status, code = _open_probe(empty_redirector.port,
                                   "/regress/no-server-read", kXR_open_read)
        assert status == kXR_error, f"expected kXR_error, got status {status}"
        assert code != kXR_IOError, \
            "redirector leaked the old raw EBADF -> kXR_IOError (3007)"
        assert code == kXR_noserver, \
            f"expected kXR_noserver (3014), got {code}"

    def test_write_open_returns_noserver_not_ebadf(self, empty_redirector):
        _wait_reachable(empty_redirector.port, EMPTY_REDIRECTOR)
        status, code = _open_probe(empty_redirector.port,
                                   "/regress/no-server-write", kXR_open_write)
        assert status == kXR_error, f"expected kXR_error, got status {status}"
        assert code == kXR_noserver, \
            f"write to serverless redirector must be kXR_noserver (3014), got {code}"

    def test_traversal_open_never_local_ebadf(self, empty_redirector):
        """Security-neg: a redirector with no local export must never resolve a
        path locally.  A traversal path is rejected at validation and NEVER
        surfaces the local-open EBADF -> kXR_IOError."""
        _wait_reachable(empty_redirector.port, EMPTY_REDIRECTOR)
        status, code = _open_probe(empty_redirector.port,
                                   "/../../../../etc/passwd", kXR_open_read)
        assert status == kXR_error, f"expected kXR_error, got status {status}"
        assert code != kXR_IOError, \
            "traversal must not reach a local open on a redirector (no EBADF leak)"
        assert code in (kXR_ArgInvalid, kXR_noserver), \
            f"traversal must be rejected cleanly (3000/3014), got {code}"


class TestRedirectorWithTarget:
    """Contrast: a static-map redirector (also rootfd == -1) that HAS a target
    still redirects — the guard is scoped to only the no-target dead end."""

    @pytest.mark.registry_servers("virtual-redir")
    def test_map_redirector_still_redirects(self):
        _wait_reachable(VIRTUAL_REDIR_PORT, "virtual-redir")
        status, _ = _open_probe(VIRTUAL_REDIR_PORT,
                                "/regress/mapped", kXR_open_read)
        assert status == kXR_redirect, \
            f"map redirector must redirect (4004), got status {status}"
