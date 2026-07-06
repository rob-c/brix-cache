"""
test_frm_control_locality.py — control-dir residency locality semantics.

Completes the materialize-to-scratch follow-up #2. With BRIX_FRM_CONTROL_DIR
set, residency markers live in a local POSIX control mount (a flat hashed stub),
not as an xattr on the export object. The probe must then resolve a missing
marker correctly: the object is ONLINE only if it actually exists in storage,
else LOST — NOT a blanket "no stub ⇒ online".

Driven through the real WLCG Tape REST surface (POST /api/v1/archiveinfo), which
maps the probe to {exists, onDisk, locality}:
  * resident object, no stub      → exists, onDisk, ONLINE
  * nearline stub in control dir   → exists, !onDisk, NEARLINE
  * object absent, no stub         → exists=false, NONE   (the fix; was ONLINE)

Self-provisioned http WebDAV + FRM; skips without xattrs.
"""

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST, free_port


from frm_helpers import xattr_ok as _xattr_ok, res_stub_path as _fnv_stub


def _post(http_port, path, obj, timeout=5):
    url = "http://%s:%d%s" % (HOST, http_port, path)
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path_factory.mktemp("frmctl")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    control = d / "control"; control.mkdir()
    queue = d / "frm.queue"
    stream_port = free_port()
    http_port = free_port()

    realdata = os.path.realpath(str(data))
    # resident object (no stub anywhere)
    (data / "online.dat").write_bytes(b"resident\n")
    # nearline: export placeholder + a control-dir stub carrying the marker
    (data / "near.dat").write_bytes(b"")
    near_stub = _fnv_stub(str(control), os.path.join(realdata, "near.dat"))
    open(near_stub, "wb").close()
    os.setxattr(near_stub, "user.frm.residency", b"nearline")
    # /gone.dat: deliberately absent on the export, with no control stub

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{stream_port};
        brix_root on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_allow_write on;
        brix_frm on;
        brix_frm_queue_path {queue};
        brix_frm_stagecmd /bin/true;
        brix_frm_control_dir {control};
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
        listen {BIND_HOST}:{http_port};
        location / {{
            brix_webdav on;
            brix_storage_backend posix:{data};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_webdav_tape_rest on;
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
            socket.create_connection((HOST, http_port), timeout=0.5).close()
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
    s.http_port = http_port
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _locality(srv, paths):
    st, body = _post(srv.http_port, "/api/v1/archiveinfo", {"paths": paths})
    assert st == 200, "archiveinfo status %r: %s" % (st, body[:200])
    j = json.loads(body.decode())
    assert "files" in j, "no files in archiveinfo: %r" % body[:200]
    return {f["path"]: f for f in j["files"]}


def test_control_dir_resident_is_online(srv):
    f = _locality(srv, ["/online.dat"])["/online.dat"]
    assert f.get("exists") is True, f
    assert f.get("onDisk") is True, f
    assert f["locality"] in ("ONLINE", "ONLINE_AND_NEARLINE"), f


def test_control_dir_stub_is_nearline(srv):
    f = _locality(srv, ["/near.dat"])["/near.dat"]
    assert f.get("exists") is True, f
    assert f.get("onDisk") is False, f
    assert f["locality"] == "NEARLINE", f


def test_control_dir_missing_object_is_lost_not_online(srv):
    """The fix: a missing object with no control stub is LOST (exists=false),
    NOT falsely reported ONLINE just because the control stub is absent."""
    f = _locality(srv, ["/gone.dat"])["/gone.dat"]
    assert f.get("exists") is False, f
    assert f.get("locality") == "NONE", f
    assert f.get("onDisk") in (False, None), f
