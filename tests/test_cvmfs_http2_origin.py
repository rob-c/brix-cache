"""Phase-85 F11 — modern upstream transport: brix_cvmfs_origin_http_version.

Theme
-----
The origin transport (the shared libcurl fill path in
src/fs/cache/origin/s3_transport.c) historically rode libcurl's default HTTP
version policy. ``brix_cvmfs_origin_http_version 1.1|2|2-direct|3`` makes the
policy operator-set, process-wide (like the origin timeout/reuse knobs):

* ``2``        — ALPN h2 over TLS / h2c Upgrade over cleartext, with libcurl's
                 automatic fallback to HTTP/1.1 when the origin declines;
* ``2-direct`` — cleartext h2 prior knowledge (the origin MUST speak h2c, e.g.
                 an nghttpd/haproxy h2c listener; no fallback);
* ``3``        — QUIC; refused at nginx -t when the linked libcurl lacks an
                 HTTP/3 backend (this box's libcurl has none — the config-time
                 refusal IS the testable contract);
* unset        — libcurl's own default, byte-frozen parity.

The negotiated version is observable: under ``brix_cvmfs_trace on`` every
upstream trace line carries ``proto=<v>``, so an H2→1.1 fallback is loud.

Origins: the python mock Stratum-1 is HTTP/1.1-only (the fallback test);
``nghttpd --no-tls`` speaks prior-knowledge h2c only (the real-H2 parity
test — it also ignores Range, exercising the driver's 200-full-body slice).

Port block srv_http (reused; suites run one at a time per session tile).
"""

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance, wait_tcp
from mock_stratum1 import make_repo, manifest
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
NGHTTPD = __import__("shutil").which("nghttpd")

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")

# ONE module-wide allocator (a fresh PortBlock would restart at base+10 and
# collide with an earlier instance still tearing down).
_BLOCK = PortBlock("srv_http")


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _forge_webroot(tmp_path: Path):
    """A repo tree on disk: the manifest plus a few CAS objects, exactly the
    layout the mock serves — so nghttpd and the mock can serve the SAME bytes."""
    root = tmp_path / "webroot"
    man = manifest(REPO, 1)                       # stamped once, then frozen
    paths = {f"/cvmfs/{REPO}/.cvmfspublished": man}
    paths.update(make_repo(REPO, 3, seed=7))
    for url_path, body in paths.items():
        f = root / url_path.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body)
    cas = sorted(p for p in paths if "/data/" in p)
    return root, man, cas, paths


def _trace_protos(srv, needle="cvmfs-trace: upstream GET"):
    out = []
    for line in srv.error_log.read_text(errors="replace").splitlines():
        if needle in line and "proto=" in line:
            out.append(line.rsplit("proto=", 1)[1].split()[0])
    return out


# ---- success: a real HTTP/2 origin, byte-identical through the cache --------

@pytest.mark.timeout(90)
@pytest.mark.skipif(NGHTTPD is None, reason="nghttpd not installed")
def test_h2_origin_parity_byte_identical(tmp_path):
    """Fills over genuine HTTP/2 (h2c prior knowledge against nghttpd) return
    the exact on-disk bytes for the manifest and a CAS object, and the trace
    proves proto=2 — not a silent downgrade."""
    root, man, cas, paths = _forge_webroot(tmp_path)
    h2_port = _BLOCK.mock()
    ngd = subprocess.Popen(
        [NGHTTPD, "--no-tls", "-d", str(root), str(h2_port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_tcp(BIND_HOST, h2_port, 10), "nghttpd did not listen"
        with srv_instance(_BLOCK, webroot=root,
                          origins=f"http://{HOST}:{h2_port}",
                          extra_directives=("brix_cvmfs_origin_http_version "
                                            "2-direct; brix_cvmfs_trace on;")
                          ) as srv:
            st, body = _get(f"{srv.base_url}/cvmfs/{REPO}/.cvmfspublished")
            assert (st, body) == (200, man)
            st, body = _get(f"{srv.base_url}{cas[0]}")
            assert (st, body) == (200, paths[cas[0]])

            protos = _trace_protos(srv)
            assert protos and set(protos) == {"2"}, protos
    finally:
        ngd.terminate()
        ngd.wait(timeout=10)


# ---- error path: H1-only origin under version 2 → loud, working fallback ----

@pytest.mark.timeout(90)
def test_h2_upgrade_falls_back_to_h1():
    """Version 2 against an HTTP/1.x-only origin (the mock ignores the h2c
    Upgrade) keeps working via libcurl's automatic fallback, and the trace
    records the 1.x downgrade so it is observable. (The mock answers as
    HTTP/1.0 — BaseHTTPRequestHandler's default — so 1.0 is the honest token.)"""
    with srv_instance(_BLOCK,
                      extra_directives=("brix_cvmfs_origin_http_version 2; "
                                        "brix_cvmfs_trace on;")) as srv:
        st, body = _get(f"{srv.base_url}/cvmfs/{REPO}/.cvmfspublished")
        assert st == 200 and body

        st, body = _get(f"{srv.base_url}{srv.objects()[0]}")
        assert st == 200 and body

        protos = _trace_protos(srv)
        assert protos and set(protos) <= {"1.0", "1.1"}, protos


# ---- security-negative / config gate ----------------------------------------

def _nginx_t(tmp_path, version_value):
    (tmp_path / "cache").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)     # -t still opens pid/error log
    conf = tmp_path / "vers.conf"
    # an unprivileged, almost-surely-free port: -t bind-checks the listener,
    # and 127.0.0.1:1 would fail on bind permission and mask the real verdict
    conf.write_text(f"""daemon off; events {{}}
http {{ server {{ listen {BIND_HOST}:64431; location /cvmfs/ {{
    brix_cvmfs on;
    brix_cache_store posix:{tmp_path}/cache;
    brix_cvmfs_origin_http_version {version_value};
}} }} }}
""")
    return subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-p", str(tmp_path)],
                          capture_output=True, text=True)


@pytest.mark.timeout(60)
def test_unsupported_and_garbage_versions_refused(tmp_path):
    """HTTP/3 without an H3-capable libcurl is refused at nginx -t (never a
    per-fill runtime failure), and a garbage value is a parse error — an
    operator cannot deploy a version the transport cannot speak."""
    r = _nginx_t(tmp_path, "3")
    assert r.returncode != 0
    assert "libcurl lacks" in r.stderr

    r = _nginx_t(tmp_path, "h9")
    assert r.returncode != 0
    assert "invalid value" in r.stderr

    # sanity: a speakable version passes the same gate
    r = _nginx_t(tmp_path, "2")
    assert r.returncode == 0, r.stderr
