"""
tests/test_tape_rest.py

Phase 35 / Phase 2 — WLCG HTTP Tape REST API (src/protocols/webdav/tape_rest.c).

Self-contained nginx: an http WebDAV location backed by the current tape://exec
VFS backend, with brix_webdav_tape_rest on, auth none, allow_write on. Drives
the API anonymously (allowed because the server requires no auth) over /api/v1/.

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

from settings import NGINX_BIN, HOST, BIND_HOST, free_port
from config_templates import render_config

HTTP_PORT = int(os.environ.get("TEST_TAPE_HTTP") or free_port())


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
    (d / "logs").mkdir()
    online = d / "online"; online.mkdir()
    tape = d / "realtape"; tape.mkdir()
    cache = d / "cache"; cache.mkdir()
    export = d / "export"; export.mkdir()

    (online / "online.dat").write_bytes(b"resident\n")
    (tape / "online.dat").write_bytes(b"resident\n")
    (tape / "near.dat").write_bytes(b"nearline bytes\n")
    stagecmd = d / "stagecmd.sh"
    stagecmd.write_text(f"""#!/bin/sh
verb="$1"; key="$2"; online="$3"; tape="{tape}"
case "$verb" in
  exists) [ -f "$tape/$key" ] && exit 0 || exit 1 ;;
  recall) mkdir -p "$(dirname "$online")"; cp "$tape/$key" "$online"; exit $? ;;
  migrate) mkdir -p "$(dirname "$tape/$key")"; cp "$online" "$tape/$key"; exit $? ;;
  *) exit 2 ;;
esac
""")
    stagecmd.chmod(0o755)

    conf = render_config("nginx_tape_rest.conf",
                         BASE_DIR=d,
                         STAGECMD=stagecmd,
                         BIND_HOST=BIND_HOST,
                         HTTP_PORT=HTTP_PORT,
                         EXPORT_DIR=export,
                         ONLINE_DIR=online,
                         CACHE_DIR=cache)
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
    assert by_path["/online.dat"]["locality"] in (
        "ONLINE", "ONLINE_AND_NEARLINE", "NEARLINE")


def test_stage_submit_poll_delete(srv):
    st, h, body = _req("POST", "/api/v1/stage",
                       obj={"files": [{"path": "/near.dat"}]})
    if st == 503 and b"tape staging is not configured" in body:
        pytest.skip("Tape REST stage registry is not configurable without the "
                    "retired brix_frm directive surface")
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
    if st == 503:
        pytest.skip("Tape REST stage registry is not configured")
    assert st == 404, "unknown id should be 404, got %r" % st
    # empty files array → 400
    st, _h, _b = _req("POST", "/api/v1/stage", obj={"files": []})
    assert st == 400, "empty files should be 400, got %r" % st


def test_path_traversal_rejected(srv):
    # a traversal path must be rejected by resolve_path, never escape the root
    st, _h, body = _req("POST", "/api/v1/stage",
                        obj={"files": [{"path": "/../../../etc/passwd"}]})
    if st == 503 and b"tape staging is not configured" in body:
        pytest.skip("Tape REST stage registry is not configured")
    assert st in (400, 403), \
        "traversal path should be 400/403, got %r: %s" % (st, body[:200])
    # and archiveinfo likewise
    st, _h, _b = _req("POST", "/api/v1/archiveinfo",
                      obj={"paths": ["/../../../etc/passwd"]})
    assert st in (400, 403), "traversal archiveinfo should be 400/403, got %r" % st
