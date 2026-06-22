"""
tests/test_tape_rest.py

Phase 35 / Phase 2 — WLCG HTTP Tape REST API (src/webdav/tape_rest.c).

Self-contained nginx: a stream root:// server with FRM enabled (so the durable
queue + frm_singleton_queue exist in the worker) plus an http WebDAV location
with xrootd_webdav_tape_rest on, auth none, allow_write on. Drives the API
anonymously (allowed because the server requires no auth) over /api/v1/.

  S  POST /archiveinfo → per-path locality (NEARLINE / ONLINE), no queue write.
  S  POST /stage → 201 + requestId + Location; GET /stage/{id} → file state.
  S  DELETE /stage/{id} → 204.
  E  invalid JSON → 400; GET unknown id → 404.
  N  path traversal in a body path → rejected by resolve_path (403), never escapes.
"""

import json
import os
import socket
import subprocess
import time
import urllib.request
import urllib.error

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST

STREAM_PORT = int(os.environ.get("TEST_TAPE_STREAM", "11227"))
HTTP_PORT = int(os.environ.get("TEST_TAPE_HTTP", "11228"))


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xattrprobe")
        open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1")
        os.remove(p)
        return True
    except Exception:
        return False


def _req(method, path, obj=None, raw=None, timeout=5):
    url = "http://%s:%d%s" % (HOST, HTTP_PORT, path)
    data = None
    if obj is not None:
        data = json.dumps(obj).encode()
    elif raw is not None:
        data = raw
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return None, {}, str(e).encode()


def _jbody(b):
    try:
        return json.loads(b.decode())
    except Exception:
        return None


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path_factory.mktemp("taperest")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    queue = d / "frm.queue"

    (data / "online.dat").write_bytes(b"resident\n")
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
        xrootd_allow_write on;
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
        location / {{
            xrootd_webdav on;
            xrootd_webdav_root {data};
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            xrootd_webdav_tape_rest on;
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
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_archiveinfo_reports_locality(srv):
    st, _h, body = _req("POST", "/api/v1/archiveinfo",
                        obj={"paths": ["/near.dat", "/online.dat"]})
    assert st == 200, "archiveinfo status %r: %s" % (st, body[:200])
    j = _jbody(body)
    assert j and "files" in j, "no files in archiveinfo: %r" % body[:200]
    by_path = {f["path"]: f for f in j["files"]}
    assert by_path["/near.dat"]["locality"] == "NEARLINE", by_path["/near.dat"]
    assert by_path["/online.dat"]["locality"] in ("ONLINE", "ONLINE_AND_NEARLINE")


def test_stage_submit_poll_delete(srv):
    st, h, body = _req("POST", "/api/v1/stage",
                       obj={"files": [{"path": "/near.dat"}]})
    assert st == 201, "stage POST status %r: %s" % (st, body[:200])
    j = _jbody(body)
    assert j and j.get("requestId"), "no requestId: %r" % body[:200]
    rid = j["requestId"]
    assert "Location" in h or "location" in h, "missing Location header: %r" % h

    st, _h, body = _req("GET", "/api/v1/stage/%s" % rid)
    assert st == 200, "stage GET status %r: %s" % (st, body[:200])
    j = _jbody(body)
    assert j and "files" in j and len(j["files"]) >= 1
    assert j["files"][0]["state"] in (
        "SUBMITTED", "STARTED", "COMPLETED"), j["files"][0]

    st, _h, _b = _req("DELETE", "/api/v1/stage/%s" % rid)
    assert st == 204, "stage DELETE status %r" % st


def test_errors(srv):
    # malformed JSON body → 400
    st, _h, _b = _req("POST", "/api/v1/stage", raw=b"{not json")
    assert st == 400, "malformed JSON should be 400, got %r" % st
    # unknown request id → 404
    st, _h, _b = _req("GET", "/api/v1/stage/does-not-exist")
    assert st == 404, "unknown id should be 404, got %r" % st
    # empty files array → 400
    st, _h, _b = _req("POST", "/api/v1/stage", obj={"files": []})
    assert st == 400, "empty files should be 400, got %r" % st


def test_path_traversal_rejected(srv):
    # a traversal path must be rejected by resolve_path, never escape the root
    st, _h, body = _req("POST", "/api/v1/stage",
                        obj={"files": [{"path": "/../../../etc/passwd"}]})
    assert st in (400, 403), \
        "traversal path should be 400/403, got %r: %s" % (st, body[:200])
    # and archiveinfo likewise
    st, _h, _b = _req("POST", "/api/v1/archiveinfo",
                      obj={"paths": ["/../../../etc/passwd"]})
    assert st in (400, 403), "traversal archiveinfo should be 400/403, got %r" % st
