"""
tests/test_cns_http.py — phase-97 §5: CNS emit from the NON-root:// planes.

test_cns.py proves the root:// data server reports its namespace mutations to
the manager.  This suite proves the other three planes do too.  Before phase-97
they did not: a federation whose data servers also accepted WebDAV, S3 or
gridftp writes ended up with a manager inventory that tracked only the root://
mutations, so a client that asked the manager about an object uploaded over
WebDAV was told it did not exist.

One export ({DATA_ROOT}) is published over four planes at once
(nginx_cns_http_data.conf).  The manager link and the `brix_cns emit` directive
live on the stream{} root:// server; the HTTP and gridftp planes resolve that
emitting server block from the cycle at emit time.  So every assertion here is
simultaneously a test of "the plane reports" and of "the plane finds the link
it does not itself own".

Coverage per plane — success, error, and security-negative:

  * success     — a mutation over the plane converges in the manager inventory
                  at the same logical path a root:// mutation would use, with
                  the size the server actually observed.
  * error       — a mutation the server REFUSED must move nothing: it may not
                  seed a phantom entry, and it may not evict a live one.
  * security/neg— a path-traversal attempt is refused by the confinement layer
                  and reports nothing, proving the emit sits BEHIND the path
                  guard rather than in front of it.  A manager that could be
                  taught about "/etc/passwd" by an unauthenticated PUT would be
                  an SSRF-grade namespace-poisoning primitive.

Serial with test_cns.py: reuses the shared "lc-cns-manager" fixed CMS port.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_cns_http.py -v
"""

import ftplib
import io
import os
import socket
import sys
import uuid

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from server_registry import NginxInstanceSpec  # noqa: E402
from settings import BIND_HOST  # noqa: E402
from test_cns import (  # noqa: E402
    kXR_ok,
    _poll_manager,
    _poll_manager_size,
    _stat,
)

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-cns"),
]

S3_BUCKET = "testbucket"
TIMEOUT = 15


# --------------------------------------------------------------------------- #
# Fixture: manager + one data server exporting the same root over four planes.
# --------------------------------------------------------------------------- #

@pytest.fixture
def http_cluster(lifecycle, tmp_path_factory):
    base = tmp_path_factory.mktemp("cns-http")
    data = base / "data"
    data.mkdir()
    # A sibling of the export, deliberately NOT exported. The traversal tests
    # aim at this directory: a vector that merely normalises back inside the
    # export proves nothing, because the resulting entry is legitimate.
    outside = base / "outside"
    outside.mkdir()

    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-manager",
        template="nginx_cns_manager.conf",
        protocol="root",
        readiness="tcp",
        reason="CNS manager for the multi-plane data server.",
    ))
    ds = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-http-data",
        template="nginx_cns_http_data.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CMS_PORT": mgr.extra_ports["CMS_PORT"]},
        reason="One export over root://+WebDAV+S3+gridftp, CMS-linked (§5).",
    ))

    # The CMS link has to connect AND log in before any plane can report over it.
    _await_link(mgr.port, ds.port)

    yield _Cluster(mgr.port, ds.port, ds.extra_ports["HTTP_PORT"],
                   ds.extra_ports["S3_PORT"], ds.extra_ports["FTP_PORT"],
                   outside)


class _Cluster:
    def __init__(self, mgr, root, dav, s3, ftp, outside):
        self.mgr, self.root, self.dav, self.s3, self.ftp = mgr, root, dav, s3, ftp
        self.outside = outside

    def dav_url(self, path):
        return f"http://{BIND_HOST}:{self.dav}{path}"

    def s3_url(self, key):
        return f"http://{BIND_HOST}:{self.s3}/{S3_BUCKET}/{key}"


def _await_link(mgr_port, ds_port):
    """Block until the data server's CMS link is up, by driving one root:// write
    (a path already proven to emit) and waiting for it at the manager.

    Sleeping a fixed interval instead would either flake on a slow host or waste
    the difference on a fast one; this waits on the actual precondition."""
    probe = f"/link-probe-{uuid.uuid4().hex}.dat"
    from test_cns import _write_file
    for _ in range(12):
        _write_file(ds_port, probe, b"link-probe")
        if _poll_manager(mgr_port, probe, want_ok=True, tries=8) == kXR_ok:
            return
    pytest.fail("data server's CMS link never came up (no CNS event landed)")


def _key():
    return f"o-{uuid.uuid4().hex}"


def _raw_http(port, method, target, body=b"", headers=()):
    """Send a request with the request-target VERBATIM.

    `requests`/urllib collapse `..` in the path before the bytes leave the
    process, so driving a traversal through them tests the CLIENT's normaliser
    and reaches the server with an already-safe path. The traversal cases have
    to put the vector on the wire themselves."""
    hdrs = [f"Host: {BIND_HOST}:{port}",
            f"Content-Length: {len(body)}",
            "Connection: close", *headers]
    req = (f"{method} {target} HTTP/1.1\r\n" + "\r\n".join(hdrs)
           + "\r\n\r\n").encode() + body

    s = socket.create_connection((BIND_HOST, port), timeout=TIMEOUT)
    try:
        s.sendall(req)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return int(buf.split(b" ", 2)[1]) if buf.startswith(b"HTTP/") else -1


def _assert_export_not_escaped(cluster, loot, logical):
    """No plane may write outside the export, and — the part this suite is
    about — the manager must never be taught such a path.

    Both spellings are checked. `cns_logical()` strips the export root to build
    the reported path, so an escaped write would either report the path relative
    to a root it does not start with (`logical`) or, failing the strip, the raw
    absolute host path. A manager holding either would redirect readers at a
    location no data server legitimately serves."""
    assert not (cluster.outside / loot).exists(), \
        f"a traversal wrote outside the export: {cluster.outside / loot}"
    assert _stat(cluster.mgr, logical)[0] != kXR_ok, \
        "a traversal poisoned the manager inventory (relative spelling)"
    assert _stat(cluster.mgr, str(cluster.outside / loot))[0] != kXR_ok, \
        "a traversal poisoned the manager inventory (absolute host path)"


# --------------------------------------------------------------------------- #
# WebDAV plane
# --------------------------------------------------------------------------- #

def _ftp(cluster):
    f = ftplib.FTP()
    f.connect(BIND_HOST, cluster.ftp, timeout=TIMEOUT)
    f.login("anonymous", "x")
    return f
