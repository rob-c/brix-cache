"""
tests/test_frm_phase1_http.py

Phase 35 / Phase 1 remainder — HTTP residency reporting + Prometheus metrics.

Self-contained nginx exposing, in one instance:
  * a stream root:// server with FRM enabled (creates the xrootd_frm_* metrics),
  * an http /metrics endpoint,
  * an http WebDAV location (auth none) for PROPFIND <xrd:locality>,
  * an http S3 location for HEAD/GET storage-class behaviour.

Asserts:
  S  /metrics exposes the xrootd_frm_* families (exporter wired, SHM struct sane).
  S  PROPFIND <xrd:locality/> of a nearline file → NEARLINE, of a resident → ONLINE.
  E  S3 GET of a nearline object → 403 InvalidObjectState; HEAD → GLACIER class.

Skips cleanly without nginx, without user-xattr support, or (for the S3 leg) if
the build serves S3 only with signed requests.
"""

import os
import socket
import subprocess
import time
import urllib.request
import urllib.error

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST, free_port

# This is a SELF-CONTAINED server (its own nginx on its own ports).  The fixed
# 11217/11218 it used to hard-code fall INSIDE the managed fleet's port range
# (11094-11247), so when the suite runs with the fleet up the stream listener
# hits "bind() to :11217 failed (Address already in use)" and the whole instance
# fails to start — leaving /metrics unreachable.  Bind OS-assigned free ports
# instead (overridable via env for debugging).
STREAM_PORT = int(os.environ.get("TEST_FRM_P1_STREAM") or free_port())
HTTP_PORT = int(os.environ.get("TEST_FRM_P1_HTTP") or free_port())


from frm_helpers import xattr_ok as _xattr_ok


def _http(method, path, body=None, headers=None, timeout=5):
    url = "http://%s:%d%s" % (HOST, HTTP_PORT, path)
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


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path_factory.mktemp("frmp1")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    queue = d / "frm.queue"

    (data / "online.dat").write_bytes(b"resident-bytes\n")
    near = data / "near.dat"
    near.write_bytes(b"")
    os.setxattr(str(near), "user.frm.residency", b"nearline")

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{STREAM_PORT};
        xrootd on;
        xrootd_root {data};
        xrootd_auth none;
        xrootd_frm on;
        xrootd_frm_queue_path {queue};
        xrootd_frm_stagecmd /bin/true;
    }}
}}
http {{
    access_log off;
    client_body_temp_path {d}/logs/cbt;
    proxy_temp_path {d}/logs/pt;
    fastcgi_temp_path {d}/logs/ft;
    uwsgi_temp_path {d}/logs/ut;
    scgi_temp_path {d}/logs/st;
    server {{
        listen {BIND_HOST}:{HTTP_PORT};
        location = /metrics {{ xrootd_metrics on; }}
        location /tapebucket/ {{
            xrootd_s3 on;
            xrootd_s3_root {data};
            xrootd_s3_bucket tapebucket;
            xrootd_s3_region us-east-1;
        }}
        location / {{
            xrootd_webdav on;
            xrootd_webdav_root {data};
            xrootd_webdav_auth none;
        }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)

    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx rejected config: %s" % chk.stderr.strip()[-300:])

    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    up = False
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, HTTP_PORT), timeout=0.5).close()
            up = True
            break
        except OSError:
            time.sleep(0.1)
    if not up:
        err = proc.stderr.read().decode(errors="replace")
        proc.terminate()
        pytest.skip("server did not start: %s" % err[-300:])

    class S:
        pass
    s = S()
    s.data = str(data)
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_metrics_exposes_frm_families(srv):
    st, _h, body = _http("GET", "/metrics")
    assert st == 200, "metrics endpoint not serving (status %r)" % st
    text = body.decode(errors="replace")
    for fam in ("xrootd_frm_requests_total",
                "xrootd_frm_stage_success_total",
                "xrootd_frm_stage_fail_total",
                "xrootd_frm_in_flight",
                "xrootd_frm_stage_latency_seconds_bucket"):
        assert fam in text, "missing FRM metric family %s in /metrics" % fam
    # fail-reason label is present and low-cardinality
    assert 'reason="copycmd"' in text


def _propfind_locality(path):
    body = (b'<?xml version="1.0"?>'
            b'<D:propfind xmlns:D="DAV:" xmlns:xrd="http://xrootd.org/2010/ns/dav">'
            b'<D:prop><xrd:locality/></D:prop></D:propfind>')
    st, _h, resp = _http("PROPFIND", path, body=body,
                         headers={"Depth": "0",
                                  "Content-Type": "application/xml"})
    return st, resp.decode(errors="replace")


def test_propfind_locality_nearline(srv):
    st, xml = _propfind_locality("/near.dat")
    if st in (401, 403, 405, None):
        pytest.skip("WebDAV PROPFIND not available (status %r)" % st)
    assert st == 207, "PROPFIND status %r: %s" % (st, xml[:200])
    assert "<xrd:locality>NEARLINE</xrd:locality>" in xml, \
        "nearline file not reported NEARLINE: %s" % xml[-400:]


def test_propfind_locality_online(srv):
    st, xml = _propfind_locality("/online.dat")
    if st in (401, 403, 405, None):
        pytest.skip("WebDAV PROPFIND not available (status %r)" % st)
    assert st == 207
    assert "<xrd:locality>ONLINE</xrd:locality>" in xml, \
        "resident file not reported ONLINE: %s" % xml[-400:]


def test_s3_nearline_head_glacier_get_forbidden(srv):
    # Confirm anonymous S3 read works at all (else skip — signed-only build).
    st, h, _b = _http("HEAD", "/tapebucket/online.dat")
    if st != 200:
        pytest.skip("anonymous S3 read not available (online HEAD %r)" % st)

    st, h, _b = _http("HEAD", "/tapebucket/near.dat")
    assert st == 200, "HEAD of nearline object: %r" % st
    sc = h.get("x-amz-storage-class") or h.get("X-Amz-Storage-Class")
    assert sc == "GLACIER", "nearline HEAD missing GLACIER storage-class: %r" % h

    st, _h, body = _http("GET", "/tapebucket/near.dat")
    assert st == 403, "GET of nearline object should be 403, got %r" % st
    assert b"InvalidObjectState" in body, \
        "403 body should be InvalidObjectState: %r" % body[:200]
