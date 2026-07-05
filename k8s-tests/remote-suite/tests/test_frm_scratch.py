# brix-remote-ok
"""
test_frm_scratch.py — FRM materialize-to-scratch + control-dir prototype.

Covers the Pillar-F follow-ups:
  * the scratch wiring: a recall is staged to a local POSIX scratch mount and
    committed to storage (force-scratch on a POSIX export, via the env knobs);
  * #1 LFN threading: the copycmd is exported $FRM_LFN, so a REAL recall script
    (frm_fake_mss.sh) fetches the right object even though it writes to a scratch
    path that does not encode the object;
  * #2 control-dir: with BRIX_FRM_CONTROL_DIR set, the residency marker lives in
    a local POSIX control mount (a flat hashed stub), not on the export object.

Self-provisioned; skips cleanly without xattrs/xrdcp.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

XRDCP = shutil.which("xrdcp")
FIXED_BYTES = b"RECALLED-VIA-SCRATCH-" + b"q" * 64 + b"\n"
TAPE_BYTES = b"REAL-TAPE-CONTENT-" + b"t" * 200 + b"\n"

# A fixed-bytes copycmd (no LFN needed — keeps a test about the scratch+commit
# mechanics alone).
FIXED_COPYCMD = """#!/bin/bash
set -u
dest="${1:-}"
[ -n "$dest" ] || exit 64
[ -n "${FRM_AUDIT_LOG:-}" ] && echo "stage $dest" >> "$FRM_AUDIT_LOG"
printf '%s' "${FRM_RECALL_TEXT:-RECALLED}" > "$dest"
"""

# A residency oracle: record the path it was asked about, then exit 1 ("nearline"
# → proceed to copycmd). Used to prove the oracle is queried on the LFN, not the
# scratch destination.
ORACLE = """#!/bin/bash
[ -n "${FRM_AUDIT_LOG:-}" ] && echo "oracle ${1:-}" >> "$FRM_AUDIT_LOG"
exit 1
"""


from frm_helpers import xattr_ok as _xattr_ok, res_stub_path as _res_stub_path


def _start_frm(d, *, force_scratch=False, control_dir=False, real_mss=False,
               oracle=False):
    """Start a self-contained POSIX FRM server. Returns (proc, ctx) or skips."""
    port = int(os.environ.get("TEST_FRM_SCRATCH_PORT") or free_port())
    d.mkdir(parents=True, exist_ok=True)
    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    scratch = d / "scratch"; scratch.mkdir()
    control = d / "control"; control.mkdir()
    tape = d / "tape"; tape.mkdir()
    queue = d / "frm.queue"
    audit = d / "audit.log"; audit.write_text("")

    copycmd = d / "copycmd.sh"
    if real_mss:
        shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"),
                    str(copycmd))
    else:
        copycmd.write_text(FIXED_COPYCMD)
    os.chmod(str(copycmd), 0o755)

    oracle_cmd = d / "oracle.sh"
    if oracle:
        oracle_cmd.write_text(ORACLE)
        os.chmod(str(oracle_cmd), 0o755)

    near = data / "near.dat"
    near.write_bytes(b"")                              # 0-byte placeholder
    if control_dir:
        # marker lives in the control mount (set by the test), NOT on the export
        pass
    else:
        os.setxattr(str(near), "user.frm.residency", b"nearline")
    if real_mss:
        (tape / "near.dat").write_bytes(TAPE_BYTES)    # the "tape" copy

    scratch_dirs = ""
    if force_scratch:
        scratch_dirs += (f"        brix_frm_stage_dir {scratch};\n"
                         "        brix_frm_force_scratch on;\n")
    if control_dir:
        scratch_dirs += f"        brix_frm_control_dir {control};\n"
    if oracle:
        scratch_dirs += f"        brix_frm_residency_cmd {oracle_cmd};\n"

    conf = f"""
worker_processes 1;
thread_pool frmpool threads=2;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
env FRM_AUDIT_LOG;
env FRM_RECALL_TEXT;
env FRM_DATA_DIR;
env FRM_TAPE_DIR;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_thread_pool frmpool;
        brix_frm on;
        brix_frm_queue_path {queue};
        brix_frm_copycmd {copycmd};
        brix_frm_copymax 4;
        brix_frm_stage_wait 1;
{scratch_dirs}    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    env = dict(os.environ)
    env.update(FRM_AUDIT_LOG=str(audit),
               FRM_RECALL_TEXT=FIXED_BYTES.decode(),
               FRM_DATA_DIR=os.path.realpath(str(data)),
               FRM_TAPE_DIR=str(tape))

    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        err = proc.stderr.read().decode(errors="replace")
        proc.terminate()
        pytest.skip(f"FRM server did not start: {err}")

    class Ctx:
        pass
    ctx = Ctx()
    ctx.port = port
    ctx.export_near = str(near)
    ctx.scratch_dir = str(scratch)
    ctx.control_dir = str(control)
    ctx.audit = str(audit)
    return proc, ctx


def _xrdcp(port, path, out, timeout=40):
    return subprocess.run([XRDCP, "-f", f"root://{HOST}:{port}/{path}", out],
                          capture_output=True, timeout=timeout)


def _audit_dests(audit):
    return [ln.split(" ", 1)[1].strip()
            for ln in open(audit) if ln.startswith("stage ")]


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


@pytest.fixture
def _guard(tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    if not _xattr_ok(str(tmp_path)):
        pytest.skip("filesystem does not support user xattrs")


def test_recall_materializes_to_scratch_then_commits(_guard, tmp_path):
    proc, ctx = _start_frm(tmp_path / "fx", force_scratch=True)
    try:
        out = str(tmp_path / "o")
        r = _xrdcp(ctx.port, "/near.dat", out)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        assert open(out, "rb").read() == FIXED_BYTES
        assert open(ctx.export_near, "rb").read() == FIXED_BYTES
        dests = _audit_dests(ctx.audit)
        assert dests and dests[-1].startswith(ctx.scratch_dir + "/")
        assert dests[-1].endswith(".scratch")
    finally:
        _stop(proc)


def test_posix_noop_copycmd_gets_export_path(_guard, tmp_path):
    """Control: force-scratch OFF → copycmd is handed the export path in place."""
    proc, ctx = _start_frm(tmp_path / "np", force_scratch=False)
    try:
        out = str(tmp_path / "o")
        r = _xrdcp(ctx.port, "/near.dat", out)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        assert open(out, "rb").read() == FIXED_BYTES
        dests = _audit_dests(ctx.audit)
        assert dests and dests[-1] == ctx.export_near
    finally:
        _stop(proc)


def test_real_recall_script_through_scratch_uses_lfn(_guard, tmp_path):
    """#1: a REAL recall script (frm_fake_mss) writing to a scratch path still
    fetches the right object — it reads $FRM_LFN, not the (scratch) dest."""
    proc, ctx = _start_frm(tmp_path / "lf", force_scratch=True, real_mss=True)
    try:
        out = str(tmp_path / "o")
        r = _xrdcp(ctx.port, "/near.dat", out)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        # the bytes the script copied from "tape" landed, via scratch, on the export
        assert open(out, "rb").read() == TAPE_BYTES
        assert open(ctx.export_near, "rb").read() == TAPE_BYTES
        dests = _audit_dests(ctx.audit)
        assert dests and dests[-1].startswith(ctx.scratch_dir + "/"), \
            "copycmd should have been handed a scratch dest"
    finally:
        _stop(proc)


def test_residency_oracle_queried_on_lfn_not_scratch(_guard, tmp_path):
    """Fix 2: the residency oracle answers "is the OBJECT resident?", so it must
    be asked about the LFN (export path) — not req->path, which under scratch is
    the empty temp we are about to recall INTO."""
    proc, ctx = _start_frm(tmp_path / "or", force_scratch=True, oracle=True)
    try:
        out = str(tmp_path / "o")
        r = _xrdcp(ctx.port, "/near.dat", out)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        lines = open(ctx.audit).read().splitlines()
        oracle = [ln.split(" ", 1)[1] for ln in lines if ln.startswith("oracle ")]
        stage = [ln.split(" ", 1)[1] for ln in lines if ln.startswith("stage ")]
        # oracle saw the export object; copycmd was handed the scratch temp
        assert oracle and oracle[-1] == os.path.realpath(ctx.export_near), oracle
        assert stage and stage[-1].startswith(ctx.scratch_dir + "/"), stage
    finally:
        _stop(proc)


def test_residency_marker_lives_in_control_dir(_guard, tmp_path):
    """#2: with a control dir, the nearline marker is a hashed stub in the control
    mount (NOT an xattr on the export); a recall clears the control stub."""
    proc, ctx = _start_frm(tmp_path / "cd", force_scratch=True, control_dir=True)
    try:
        # The export object carries NO xattr; make it nearline via a control stub.
        stub = _res_stub_path(ctx.control_dir, os.path.realpath(ctx.export_near))
        open(stub, "wb").close()
        os.setxattr(stub, "user.frm.residency", b"nearline")
        # sanity: the export object itself has no residency xattr
        assert "user.frm.residency" not in os.listxattr(ctx.export_near)

        out = str(tmp_path / "o")
        r = _xrdcp(ctx.port, "/near.dat", out)        # nearline → recall → serve
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        assert open(out, "rb").read() == FIXED_BYTES

        # On a successful recall the worker flips residency ONLINE → control stub
        # removed (no stub == online).
        assert not os.path.exists(stub), "control residency stub not cleared online"
    finally:
        _stop(proc)
