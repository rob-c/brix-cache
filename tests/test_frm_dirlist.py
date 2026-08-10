"""frm (tape/MSS) namespace enumeration — parity audit §3 row 7.

Pure-tape dirlist used to be ENOTSUP: the MSS adapter vtable had no directory
verb. A new optional `list` slot (the stock `rsscmd dread` analog) now backs
driver opendir/readdir/closedir:

  * stub adapter — readdir of the local tape directory (the offline namespace),
    WITHOUT recalling anything and without leaking the .online/.recalling
    bookkeeping roots.
  * exec adapter — `$BRIX_FRM_STAGECMD dread <key> ''` with stdout captured,
    one entry per line, trailing '/' = directory; a stagecmd that does not know
    the verb exits nonzero and the key stays not-enumerable (old behaviour).

Coverage: stub listing over live root:// kXR_dirlist (names present, no
bookkeeping leak, no recall side-effect); missing dir errors; exec dread via a
shell-script stagecmd. Self-contained (no shared fleet).
"""

import os
import socket
import stat as statmod
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H

kXR_dirlist = 3004


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _launch(tmp_path, backend, extra_env=None):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    port = _free_port()
    conf = tmp_path / "nginx.conf"
    stagecmd_line = ""
    if extra_env and "BRIX_FRM_STAGECMD" in extra_env:
        # nginx scrubs the worker environment: pin the exec adapter's stagecmd
        # with the inline `env VAR=value` form so it reaches the worker.
        stagecmd_line = f"env BRIX_FRM_STAGECMD={extra_env['BRIX_FRM_STAGECMD']};\n"
    conf.write_text(
        "daemon on;\n"
        "worker_processes 1;\n"
        + stagecmd_line +
        f"pid {logs}/nginx.pid;\n"
        f"error_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_export {ns};\n"
        "    brix_auth none;\n"
        "    brix_allow_write on;\n"
        f"    brix_storage_backend {backend};\n"
        f"    brix_cache_store posix:{cache};\n"
        "    brix_cache_export /;\n"
        "  }\n"
        "}\n")
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    t = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30, env=env)
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30, env=env)
    assert r.returncode == 0, f"nginx failed to start: {r.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return port, conf


def _stop(tmp_path, conf):
    subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf),
                    "-s", "quit"], capture_output=True, timeout=30)
    time.sleep(0.2)


def _dirlist(sock, stream, path):
    body = b"\x00" * 15 + b"\x00"   # reserved[15] + options byte
    return H._send_req(sock, stream, kXR_dirlist, body=body,
                       payload=path.encode() + b"\x00")


kXR_mkdir = 3008


def _mkdir(sock, stream, path, mkpath=True, mode=0o755):
    # ClientMkdirRequest: options[1] reserved[13] mode[2]
    body = struct.pack(">B13sH", 0x01 if mkpath else 0x00, b"\x00" * 13, mode)
    return H._send_req(sock, stream, kXR_mkdir, body=body,
                       payload=path.encode() + b"\x00")


def test_stub_tape_dirlist(tmp_path):
    """(success) the offline tape namespace lists over kXR_dirlist without any
    recall and without leaking the .online/.recalling bookkeeping roots."""
    tape = tmp_path / "tape"
    (tape / "sub").mkdir(parents=True)
    (tape / "a.bin").write_bytes(b"A" * 32)
    (tape / "b.bin").write_bytes(b"B" * 32)
    (tape / "sub" / "c.bin").write_bytes(b"C" * 8)

    port, conf = _launch(tmp_path, f"frm://stub{tape}")
    primary = None
    try:
        H.ANON_HOST = BIND_HOST
        primary, sessid, stream = H._establish_primary(port)

        status, body = _dirlist(primary, stream, "/")
        assert status in (H.kXR_ok, H.kXR_oksofar), f"dirlist status={status}"
        names = body.rstrip(b"\x00").decode().split("\n")
        for want in ("a.bin", "b.bin", "sub"):
            assert want in names, f"{want} missing from tape listing: {names}"
        assert not any(n.startswith(".") for n in names), \
            f"bookkeeping root leaked into the listing: {names}"

        # A subdirectory lists too.
        status, body = _dirlist(primary, stream, "/sub")
        assert status in (H.kXR_ok, H.kXR_oksofar)
        assert "c.bin" in body.decode(), body

        # Enumeration is pure: nothing was recalled into the online buffer.
        assert not (tape / ".online").exists() \
            or not any((tape / ".online").rglob("*")), \
            "dirlist triggered a recall (online buffer populated)"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_missing_dir_errors(tmp_path):
    """(error) a dirlist of an absent tape directory is an error, not an empty
    fabricated listing."""
    tape = tmp_path / "tape"
    tape.mkdir()
    port, conf = _launch(tmp_path, f"frm://stub{tape}")
    primary = None
    try:
        H.ANON_HOST = BIND_HOST
        primary, sessid, stream = H._establish_primary(port)
        status, _ = _dirlist(primary, stream, "/no/such/dir")
        assert status == H.kXR_error, f"expected kXR_error, got {status}"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_stub_rcreate(tmp_path):
    """(rcreate/stub) kXR_mkdir on a tape export creates the directory on the
    MSS (the local tape root for the stub) — and it lists afterwards."""
    tape = tmp_path / "tape"
    tape.mkdir()
    port, conf = _launch(tmp_path, f"frm://stub{tape}")
    primary = None
    try:
        H.ANON_HOST = BIND_HOST
        primary, sessid, stream = H._establish_primary(port)

        status, _ = _mkdir(primary, stream, "/newset/2026")
        assert status == H.kXR_ok, f"tape mkdir failed: {status}"
        assert (tape / "newset" / "2026").is_dir(), \
            "rcreate did not land on the MSS (tape dir missing)"

        status, body = _dirlist(primary, stream, "/newset")
        assert status in (H.kXR_ok, H.kXR_oksofar)
        assert "2026" in body.decode(), body
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_exec_rcreate_verb(tmp_path):
    """(rcreate/exec) kXR_mkdir drives `$BRIX_FRM_STAGECMD rcreate <key>`; a
    stagecmd that refuses the verb makes the mkdir an error."""
    base = tmp_path / "buffer"
    base.mkdir()
    marker = tmp_path / "rcreate.log"
    stagecmd = tmp_path / "stagecmd.sh"
    stagecmd.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        f"  rcreate) echo \"$2\" >> {marker}; exit 0 ;;\n"
        "  exists) exit 0 ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n")
    stagecmd.chmod(stagecmd.stat().st_mode | statmod.S_IEXEC)

    port, conf = _launch(tmp_path, f"tape://exec{base}",
                         extra_env={"BRIX_FRM_STAGECMD": str(stagecmd)})
    primary = None
    try:
        H.ANON_HOST = BIND_HOST
        primary, sessid, stream = H._establish_primary(port)
        status, _ = _mkdir(primary, stream, "/archive/run7")
        assert status == H.kXR_ok, f"exec rcreate failed: {status}"
        assert marker.exists() and "/archive/run7" in marker.read_text(), \
            "stagecmd did not receive the rcreate verb/key"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_exec_dread(tmp_path):
    """(exec adapter) `$BRIX_FRM_STAGECMD dread` drives the listing: one name
    per line, trailing '/' marks a directory."""
    base = tmp_path / "buffer"
    base.mkdir()
    stagecmd = tmp_path / "stagecmd.sh"
    stagecmd.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  dread) printf 'tapefile.dat\\narchive-dir/\\n'; exit 0 ;;\n"
        "  exists) exit 0 ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n")
    stagecmd.chmod(stagecmd.stat().st_mode | statmod.S_IEXEC)

    port, conf = _launch(tmp_path, f"tape://exec{base}",
                         extra_env={"BRIX_FRM_STAGECMD": str(stagecmd)})
    primary = None
    try:
        H.ANON_HOST = BIND_HOST
        primary, sessid, stream = H._establish_primary(port)
        status, body = _dirlist(primary, stream, "/")
        assert status in (H.kXR_ok, H.kXR_oksofar), f"dirlist status={status}"
        text = body.decode()
        assert "tapefile.dat" in text, f"dread entry missing: {text!r}"
        assert "archive-dir" in text, f"dread dir entry missing: {text!r}"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)
