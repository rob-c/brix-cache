"""
tests/test_frm_phase4_engines.py

Phase 35 / Phase 4 engines — F3 (residency-cmd oracle) + F5 (checksum-on-stage),
end-to-end through the stage agent.

F3: with brix_frm_residency_cmd set, the stage agent consults the oracle BEFORE
    copying. Oracle exit 0 = "already resident" → the copycmd is skipped and the
    open is served from disk (proven: the served bytes are the on-disk content and
    the fake-MSS audit log records no copy).

F5: with a per-file checksum on a Tape REST stage request, the agent verifies the
    recalled file after copy. A correct checksum → COMPLETED; a wrong one → FAILED
    and brix_frm_stage_fail_total{reason="verify"} increments.

Self-contained; skips cleanly without nginx / xrdcp / xattrs / requests.
"""

import os
import shutil
import subprocess
import time
import zlib
import json
import urllib.request

import pytest

from cmdscripts import frm_oracle_online
from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frm-p4eng")]

XRDCP = shutil.which("xrdcp")


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xp"); open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1"); os.remove(p); return True
    except Exception:
        return False


def _start_or_skip(lifecycle, spec):
    """Start via the lifecycle harness, skipping (not erroring) when nginx
    rejects the config — the legacy brix_frm* directive surface was disabled
    2026-06-30, so a build without it must skip exactly as the old nginx -t
    guard did."""
    try:
        return lifecycle.start(spec)
    except RegistryCommandFailure as exc:
        pytest.skip("nginx rejected config: %s" % str(exc)[-300:])


# --------------------------------------------------------------------------- F3
@pytest.fixture
def f3(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built")
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    d = tmp_path / "frmf3"; d.mkdir()
    if not _xattr_ok(str(d)):
        pytest.skip("no user xattrs")
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()
    audit = d / "audit.log"

    copycmd = str(d / "copy.py")
    shutil.copy(os.path.join(os.path.dirname(__file__), "cmdscripts", "frm_fake_mss.py"), copycmd)
    os.chmod(copycmd, 0o755)
    # residency oracle: always reports "online" (exit 0) → agent skips the copy.
    oracle = frm_oracle_online.install(d)

    # nearline-marked file that ALREADY has its real bytes on disk; the tape copy
    # is DIFFERENT so we can tell whether the (skipped) copy ran.
    disk_bytes = b"DISK-RESIDENT-CONTENT\n"
    (tape / "f.dat").write_bytes(b"TAPE-WOULD-OVERWRITE\n")
    (data / "f.dat").write_bytes(disk_bytes)
    os.setxattr(str(data / "f.dat"), "user.frm.residency", b"nearline")

    endpoint = _start_or_skip(lifecycle, NginxInstanceSpec(
        name="lc-frm-p4eng-f3",
        template="nginx_lc_frm_phase4_engines_f3.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "QUEUE_PATH": str(d / "frm.queue"),
            "COPY_CMD": copycmd,
            "ORACLE_CMD": oracle,
        },
        env={
            "FRM_DATA_DIR": os.path.realpath(str(data)),
            "FRM_TAPE_DIR": str(tape),
            "FRM_LATENCY_MS": "100",
            "FRM_AUDIT_LOG": str(audit),
        },
        reason="Phase 4 F3 residency-oracle stage-agent engine"))

    class S: pass
    s = S(); s.port = endpoint.port; s.audit = str(audit); s.disk_bytes = disk_bytes
    yield s


def test_f3_oracle_online_skips_copy(f3, tmp_path):
    out = str(tmp_path / "f.out")
    r = subprocess.run([XRDCP, "-f", "-s",
                        f"root://{HOST}:{f3.port}//f.dat", out],
                       capture_output=True, timeout=30)
    assert r.returncode == 0, "xrdcp failed: %s" % r.stderr.decode(errors="replace")
    # served from disk (copy was skipped by the oracle) → disk bytes, not tape
    assert open(out, "rb").read() == f3.disk_bytes
    # the fake-MSS copycmd never ran
    n = 0
    if os.path.exists(f3.audit):
        n = sum(1 for ln in open(f3.audit) if ln.startswith("stage"))
    assert n == 0, "oracle said online but the copycmd still ran (%d times)" % n


# --------------------------------------------------------------------------- F5
@pytest.fixture
def f5(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built")
    d = tmp_path / "frmf5"; d.mkdir()
    if not _xattr_ok(str(d)):
        pytest.skip("no user xattrs")
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()

    copycmd = str(d / "copy.py")
    shutil.copy(os.path.join(os.path.dirname(__file__), "cmdscripts", "frm_fake_mss.py"), copycmd)
    os.chmod(copycmd, 0o755)

    content = b"CHECKSUMMED-TAPE-CONTENT-" + b"k" * 300 + b"\n"
    adler = "%08x" % (zlib.adler32(content) & 0xffffffff)
    for name in ("good.dat", "bad.dat"):
        (tape / name).write_bytes(content)
        (data / name).write_bytes(b"")
        os.setxattr(str(data / name), "user.frm.residency", b"nearline")

    endpoint = _start_or_skip(lifecycle, NginxInstanceSpec(
        name="lc-frm-p4eng-f5",
        template="nginx_lc_frm_phase4_engines_f5.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "QUEUE_PATH": str(d / "frm.queue"),
            "COPY_CMD": copycmd,
        },
        env={
            "FRM_DATA_DIR": os.path.realpath(str(data)),
            "FRM_TAPE_DIR": str(tape),
            "FRM_LATENCY_MS": "100",
            "FRM_AUDIT_LOG": str(d / "audit.log"),
        },
        reason="Phase 4 F5 checksum-on-stage recall engine"))

    class S: pass
    s = S(); s.port = endpoint.port
    s.mport = endpoint.extra_ports["METRICS_PORT"]; s.adler = adler
    yield s


def _tape_stage(mport, path, checksum):
    body = json.dumps({"files": [{"path": path, "checksum": checksum,
                                  "checksumType": "adler32"}]}).encode()
    req = urllib.request.Request("http://%s:%d/api/v1/stage" % (HOST, mport),
                                 data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())["requestId"]


def _stage_state(mport, rid):
    with urllib.request.urlopen(
            "http://%s:%d/api/v1/stage/%s" % (HOST, mport, rid), timeout=5) as r:
        return json.loads(r.read())["files"][0]["state"]


def _metric(mport, name, label=None):
    with urllib.request.urlopen(
            "http://%s:%d/metrics" % (HOST, mport), timeout=5) as r:
        for ln in r.read().decode(errors="replace").splitlines():
            key = name + (("{" + label + "}") if label else " ")
            if ln.startswith(name) and (label is None or label in ln):
                try:
                    return float(ln.split()[-1])
                except ValueError:
                    pass
    return 0.0


def _poll_state(mport, rid, want, t=20):
    end = time.time() + t
    last = None
    while time.time() < end:
        last = _stage_state(mport, rid)
        if last in want:
            return last
        time.sleep(0.3)
    return last


# F5 checksum-on-stage verify — deferred by the src/frm dissolution.
#
# Both cases below drive the Tape REST /stage front door and then poll for the
# stage-agent to DRAIN the durable request to COMPLETED/FAILED and to increment
# brix_frm_stage_fail_total{reason="verify"}.  That draining stage agent (the
# legacy FRM queue/scheduler worker-init) is retired — see
# src/core/config/process_server_init.c: "The legacy FRM queue/scheduler/purge
# worker-init is retired — the recall is driven by the [backend] on read".  On the
# live surface a POST /stage is durably RECORDED (state SUBMITTED) but nothing
# advances or checksum-verifies it, so there is no live behaviour these two cases
# can assert.  The request-acceptance half is covered by tests/test_tape_rest.py
# (which asserts state in {SUBMITTED, STARTED, COMPLETED}); checksum verify-on-stage
# reappears with the stage-engine RECALL integration flagged in
# src/protocols/root/query/prepare.c.  Skipped (not deleted) so both re-arm when
# that integration lands.
_F5_DEFERRED = ("checksum verify-on-stage requires the retired FRM stage-agent "
                "drain; the live registry records a stage request (SUBMITTED) but "
                "does not drain/verify it — see process_server_init.c and "
                "prepare.c. Re-arms with the stage-engine RECALL integration.")


@pytest.mark.skip(reason=_F5_DEFERRED)
def test_f5_correct_checksum_completes(f5):
    rid = _tape_stage(f5.mport, "/good.dat", f5.adler)
    st = _poll_state(f5.mport, rid, {"COMPLETED", "FAILED"})
    assert st == "COMPLETED", "correct checksum should complete, got %r" % st


@pytest.mark.skip(reason=_F5_DEFERRED)
def test_f5_wrong_checksum_fails_verify(f5):
    before = _metric(f5.mport, "brix_frm_stage_fail_total", 'reason="verify"')
    rid = _tape_stage(f5.mport, "/bad.dat", "deadbeef")
    st = _poll_state(f5.mport, rid, {"FAILED"})
    assert st == "FAILED", "wrong checksum should fail the recall, got %r" % st
    after = _metric(f5.mport, "brix_frm_stage_fail_total", 'reason="verify"')
    assert after > before, \
        "verify-fail metric did not increment (%r → %r)" % (before, after)
