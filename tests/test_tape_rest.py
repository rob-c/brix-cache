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
import urllib.request
import urllib.error

import pytest

from cmdscripts import frm_stagecmd
from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tape-rest")]

HTTP_PORT = None   # bound to the started endpoint's fixed port in the fixture


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


@pytest.fixture
def srv(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path
    online = d / "online"; online.mkdir()
    tape = d / "realtape"; tape.mkdir()
    cache = d / "cache"; cache.mkdir()
    export = d / "export"; export.mkdir()
    control = d / "control"; control.mkdir()
    queue = d / "frm.queue"

    (online / "online.dat").write_bytes(b"resident\n")
    (tape / "online.dat").write_bytes(b"resident\n")
    (tape / "near.dat").write_bytes(b"nearline bytes\n")
    # Tape MSS adapter — exists/recall/migrate only (any other verb exits 2);
    # the REST key is used verbatim (no leading-slash strip). Config rides in a
    # JSON sidecar next to the copied script.
    stagecmd = frm_stagecmd.install(
        d, name="stagecmd.py", tape=str(tape), strip_slash=False,
        verbs=["exists", "recall", "migrate"], unknown_exit=2)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-tape-rest",
        template="nginx_lc_tape_rest.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "EXPORT_DIR": str(export),
                         "ONLINE_DIR": str(online),
                         "CACHE_DIR": str(cache),
                         "QUEUE_PATH": str(queue),
                         "CONTROL_DIR": str(control)},
        env={"BRIX_FRM_STAGECMD": str(stagecmd)},
        reason="wlcg tape rest api"))

    global HTTP_PORT
    HTTP_PORT = ep.port

    class S:
        pass
    s = S()
    yield s


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
