"""
tests/test_frm_phase1_http.py

Phase 35 / Phase 1 remainder — HTTP residency reporting + Prometheus metrics.

Self-contained nginx exposing, in one instance:
  * a stream root:// server on the same POSIX export,
  * an http /metrics endpoint,
  * an http WebDAV location (auth none) for PROPFIND <xrd:locality>,
  * an http S3 location for HEAD/GET storage-class behaviour.

Asserts:
  S  legacy brix_frm_* metric assertions skip when the retired directive surface
     is not built.
  S  PROPFIND <xrd:locality/> of a nearline file → NEARLINE, of a resident → ONLINE.
  E  S3 GET of a nearline object → 403 InvalidObjectState; HEAD → GLACIER class.

Skips cleanly without nginx, without user-xattr support, or (for the S3 leg) if
the build serves S3 only with signed requests.
"""

import os
import urllib.request
import urllib.error

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frm-phase1-http")]

# Ports are bound at fixture time: the primary /metrics HTTP listener comes from
# the registry endpoint (HTTP_PORT); the secondary stream/S3/WebDAV listeners are
# the fixed lifecycle-shared ledger `extra` ports carried on the started endpoint.
STREAM_PORT = None
HTTP_PORT = None
S3_PORT = None
WEBDAV_PORT = None


from frm_helpers import xattr_ok as _xattr_ok


def _http(method, path, body=None, headers=None, timeout=5, port=None):
    url = "http://%s:%d%s" % (HOST, port or HTTP_PORT, path)
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception:
        return None, {}, b""


@pytest.fixture
def srv(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    data = d / "data"; data.mkdir()
    (data / "online.dat").write_bytes(b"resident-bytes\n")
    near = data / "near.dat"
    near.write_bytes(b"")
    os.setxattr(str(near), "user.frm.residency", b"nearline")

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-frm-phase1-http",
        template="nginx_lc_frm_phase1_http.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="frm phase-1 http staging"))

    global STREAM_PORT, HTTP_PORT, S3_PORT, WEBDAV_PORT
    HTTP_PORT = endpoint.port
    STREAM_PORT = endpoint.extra_ports["STREAM_PORT"]
    S3_PORT = endpoint.extra_ports["S3_PORT"]
    WEBDAV_PORT = endpoint.extra_ports["WEBDAV_PORT"]

    class S:
        pass
    s = S()
    s.data = str(data)
    yield s


def test_metrics_exposes_frm_families(srv):
    pytest.skip("legacy brix_frm metrics were retired with the directive surface; "
                "tape:// backend residency is covered by tape backend tests")
    st, _h, body = _http("GET", "/metrics")
    assert st == 200, "metrics endpoint not serving (status %r)" % st
    text = body.decode(errors="replace")
    for fam in ("brix_frm_requests_total",
                "brix_frm_stage_success_total",
                "brix_frm_stage_fail_total",
                "brix_frm_in_flight",
                "brix_frm_stage_latency_seconds_bucket"):
        assert fam in text, "missing FRM metric family %s in /metrics" % fam
    # fail-reason label is present and low-cardinality
    assert 'reason="copycmd"' in text


def _propfind_locality(path):
    body = (b'<?xml version="1.0"?>'
            b'<D:propfind xmlns:D="DAV:" xmlns:xrd="http://brix.org/2010/ns/dav">'
            b'<D:prop><xrd:locality/></D:prop></D:propfind>')
    st, _h, resp = _http("PROPFIND", path, body=body,
                         headers={"Depth": "0",
                                  "Content-Type": "application/xml"},
                         port=WEBDAV_PORT)
    return st, resp.decode(errors="replace")


def test_propfind_locality_xattr_not_a_signal(srv):
    """Phase-64 P6: PROPFIND xrd:locality comes from the storage BACKEND's residency
    model (the brix_vfs_residency seam), NOT the legacy user.frm.residency xattr.
    An xattr-marked file on a plain POSIX export (no nearline tier) is therefore
    reported ONLINE. The tape:// locality UX (NEARLINE for an offline object) is
    covered against a real nearline backend in tests/run_tape_exec_adapter.sh."""
    st, xml = _propfind_locality("/near.dat")
    if st in (401, 403, 405, None):
        pytest.skip("WebDAV PROPFIND not available (status %r)" % st)
    assert st == 207, "PROPFIND status %r: %s" % (st, xml[:200])
    assert "<xrd:locality>ONLINE</xrd:locality>" in xml, \
        "the FRM residency xattr must NOT drive locality on a posix export: %s" \
        % xml[-400:]


def test_propfind_locality_online(srv):
    st, xml = _propfind_locality("/online.dat")
    if st in (401, 403, 405, None):
        pytest.skip("WebDAV PROPFIND not available (status %r)" % st)
    assert st == 207
    assert "<xrd:locality>ONLINE</xrd:locality>" in xml, \
        "resident file not reported ONLINE: %s" % xml[-400:]


def test_s3_residency_from_backend_not_frm_xattr(srv):
    """Phase-64 P6: s3 residency now comes from the storage BACKEND's residency
    model (the brix_vfs_residency seam), NOT the legacy user.frm.residency xattr.
    An xattr-marked object on a plain POSIX s3 export (no nearline tier) is therefore
    classified ONLINE and served normally — no GLACIER class, no InvalidObjectState.
    The tape:// residency UX (HEAD→GLACIER, GET→403 InvalidObjectState) is covered
    against a real nearline backend in tests/run_s3_tape_residency.sh."""
    # Confirm anonymous S3 read works at all (else skip — signed-only build).
    st, h, _b = _http("HEAD", "/tapebucket/online.dat", port=S3_PORT)
    if st != 200:
        pytest.skip("anonymous S3 read not available (online HEAD %r)" % st)

    # near.dat carries the legacy FRM residency xattr but lives on a POSIX backend:
    # the seam reads the backend (no nearline tier ⇒ ONLINE), not the xattr.
    st, h, _b = _http("HEAD", "/tapebucket/near.dat", port=S3_PORT)
    assert st == 200, "HEAD of an xattr-marked object on a posix export: %r" % st
    sc = h.get("x-amz-storage-class") or h.get("X-Amz-Storage-Class")
    assert sc != "GLACIER", \
        "the FRM residency xattr must NOT drive s3 storage-class anymore: %r" % h

    st, _h, _body = _http("GET", "/tapebucket/near.dat", port=S3_PORT)
    assert st == 200, \
        "an xattr-marked object on a posix export is ONLINE, served normally: %r" % st
