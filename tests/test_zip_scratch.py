"""
test_zip_scratch.py — ZIP CONSUME via materialize-to-scratch (Pillar F #3).

ZIP serves a member by random-access pread (+ sendfile for stored members) over
the archive fd — which a storage backend with no kernel fd cannot provide. The
materialize-to-scratch seam copies the archive into a local POSIX scratch and
reads THAT. Exercised on a POSIX export via BRIX_ZIP_FORCE_SCRATCH=1 +
BRIX_ZIP_STAGE_DIR; the member must still serve byte-exact, and the server logs
that it staged the archive. Self-provisioned; reuses test_zip_member's raw-wire
helpers.
"""

import os
import socket
import subprocess
import time
import zipfile

import pytest

from settings import NGINX_BIN, free_port
from config_templates import render_config
from test_zip_member import _session, _open, _read, kXR_ok, STORED


def _wait_listen(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def _start(tmp_path, force_scratch):
    base = tmp_path
    data = base / "data"; logs = base / "logs"; stage = base / "stage"
    for p in (data, logs, stage):
        p.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(data / "a.zip", "w") as z:
        z.writestr("stored.txt", STORED, compress_type=zipfile.ZIP_STORED)

    port = free_port()
    zip_dirs = ""
    if force_scratch:
        zip_dirs = (f"brix_zip_stage_dir {stage}; "
                    "brix_zip_force_scratch on; ")
    cfg = base / "nginx.conf"
    cfg.write_text(render_config("nginx_zip_scratch.conf",
                                 BASE_DIR=base,
                                 LOG_DIR=logs,
                                 PORT=port,
                                 DATA_DIR=data,
                                 ZIP_DIRECTIVES=zip_dirs))
    proc = subprocess.Popen([NGINX_BIN, "-c", str(cfg), "-p", str(base)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(port):
        proc.terminate()
        pytest.skip("zip scratch nginx did not come up")

    class Ctx:
        pass
    ctx = Ctx()
    ctx.port = port
    ctx.errlog = str(logs / "err.log")
    return proc, ctx


def _read_member(port, member):
    s = _session(port)
    try:
        st, body = _open(s, f"/a.zip?xrdcl.unzip={member}")
        assert st == kXR_ok, f"open failed status={st}"
        st, data = _read(s, body[:4], 0, 65536)
        assert st == kXR_ok
        return data
    finally:
        s.close()


@pytest.fixture
def _guard():
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not built")


def test_zip_member_served_via_scratch(_guard, tmp_path):
    proc, ctx = _start(tmp_path, force_scratch=True)
    try:
        # served byte-exact even though the archive was read from a staged copy
        assert _read_member(ctx.port, "stored.txt") == STORED
        # proof the materialize-to-scratch path ran
        log = open(ctx.errlog).read()
        assert "archive staged to scratch" in log, \
            "force-scratch did not stage the zip archive"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def test_zip_member_in_place_when_not_forced(_guard, tmp_path):
    """Control: no force → the archive is read in place (no staging)."""
    proc, ctx = _start(tmp_path, force_scratch=False)
    try:
        assert _read_member(ctx.port, "stored.txt") == STORED
        log = open(ctx.errlog).read()
        assert "archive staged to scratch" not in log
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
