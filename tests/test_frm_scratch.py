"""
test_frm_scratch.py — FRM nearline recall through the frm:// storage backend.

Rewritten (2026-07-17) for the backend-composition surface that replaced the
removed ``brix_frm*`` directive family (removed 2026-06-30).  A nearline object
lives behind an MSS adapter:

  * ``frm://exec/<base>`` shells the recall/residency verbs out to the operator
    stage command ``$BRIX_FRM_STAGECMD <verb> <key> <online>`` (the classic FRM
    model), or
  * ``frm://stub/<tape>`` simulates tape with a local directory,

composed with a required ``brix_cache_store posix:<cache>`` recall target.  A
read RECALLS the object into the online buffer (``<base>/.online/<key>``) and
serves it byte-exact through the cache tier.

Covered, on the live data plane (mapping the old scratch/control-dir prototype
onto the new surface):

  * exec-adapter recall — the stage command's ``recall`` verb materialises the
    object into the online buffer and its bytes are served (the old
    materialise-to-scratch-then-commit, now online-buffer -> cache);
  * key threading — the stage command is handed the object KEY (LFN), so a
    by-key fetch serves the right bytes regardless of the online-buffer path
    (the old ``$FRM_LFN`` threading);
  * residency — the ``exists`` verb is queried on the key BEFORE any recall
    (the old residency oracle);
  * a genuinely-absent object (``exists`` -> non-zero) is reported not-found and
    is never fabricated (error + security-negative);
  * stub-adapter recall from a local tape directory, no stage command.

Self-provisioned; skips cleanly only when xrdcp is unavailable.
"""

import os
import shutil
import subprocess

import pytest

from cmdscripts import frm_stagecmd
from settings import HOST
from server_registry import NginxInstanceSpec

# Serialised onto one worker: every test drives a self-contained frm:// server on
# the adapter's single fixed ledger port (lc-frm-exec / lc-frm-stub), reusing it
# across tests since each test closes its harness at teardown.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frm-scratch")]

XRDCP = shutil.which("xrdcp")
TAPE_BYTES = b"REAL-TAPE-CONTENT-" + b"t" * 200 + b"\n"


def _start(harness, tmp_path, *, adapter="exec", nearline=True):
    """Start a self-contained frm:// server (exec or stub) via the harness.

    Returns (endpoint, audit_path).  ``audit_path`` is meaningful for the exec
    adapter only; the harness stops the server at fixture teardown.
    """
    cache = tmp_path / "cache"; cache.mkdir()
    audit = tmp_path / "audit.log"; audit.write_text("")
    env = {}

    if adapter == "exec":
        base = tmp_path / "base"; base.mkdir()
        tape = tmp_path / "tape"; tape.mkdir()
        if nearline:
            (tape / "near.dat").write_bytes(TAPE_BYTES)
        # Exec MSS adapter — every verb is appended to the audit log as
        # "verb key online". Tape dir + audit path ride in a JSON sidecar (nginx
        # rewrites its worker environ; only argv + BRIX_FRM_STAGECMD survive).
        stagecmd = frm_stagecmd.install(tmp_path, tape=str(tape), audit=str(audit))
        storage = f"frm://exec{base}"
        env["BRIX_FRM_STAGECMD"] = stagecmd
    else:  # stub: the base directory IS the tape (offline objects live in it)
        tape = tmp_path / "tape"; tape.mkdir()
        if nearline:
            (tape / "near.dat").write_bytes(TAPE_BYTES)
        storage = f"frm://stub{tape}"

    name = f"lc-frm-{adapter}"
    endpoint = harness.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_frm_exec.conf",
        protocol="root",
        readiness="tcp",
        template_values={"STORAGE_BACKEND": storage, "CACHE_DIR": str(cache)},
        env=env,
        reason="frm nearline recall"))
    return endpoint, str(audit)


def _xrdcp(port, path, out, timeout=60):
    return subprocess.run(
        [XRDCP, "-f", f"root://{HOST}:{port}/{path}", out],
        capture_output=True, timeout=timeout)


def _audit(path):
    """Parse the stage-command audit log into (verb, key, online) tuples."""
    verbs = []
    with open(path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split(" ", 2)
            if parts and parts[0]:
                verbs.append(tuple(parts + [""] * (3 - len(parts))))
    return verbs


@pytest.fixture
def frm(lifecycle):
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    return lifecycle


def test_exec_recall_serves_nearline_object(frm, tmp_path):
    """The exec adapter's recall verb materialises the object into the online
    buffer and the bytes are served byte-exact through the cache tier."""
    ep, audit = _start(frm, tmp_path)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == TAPE_BYTES
    assert any(v[0] == "recall" for v in _audit(audit)), _audit(audit)


def test_stagecmd_recall_receives_object_key(frm, tmp_path):
    """Key threading: the recall verb is handed the object KEY (the LFN
    ``near.dat``), not the online-buffer path, so a by-key fetch serves the right
    bytes."""
    ep, audit = _start(frm, tmp_path)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    recalls = [v for v in _audit(audit) if v[0] == "recall"]
    assert recalls and recalls[-1][1] == "near.dat", _audit(audit)
    assert open(out, "rb").read() == TAPE_BYTES


def test_residency_probed_before_recall(frm, tmp_path):
    """The residency ``exists`` verb is queried on the object key before any
    recall is issued (the old residency-oracle-on-the-LFN contract)."""
    ep, audit = _start(frm, tmp_path)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    verbs = [v[0] for v in _audit(audit)]
    assert "exists" in verbs, verbs
    if "recall" in verbs:
        assert verbs.index("exists") < verbs.index("recall"), verbs
    exists = [v for v in _audit(audit) if v[0] == "exists"]
    assert exists and all(v[1] == "near.dat" for v in exists), exists


def test_absent_object_reports_not_found(frm, tmp_path):
    """Error + security-negative: an object that is not on tape (``exists`` ->
    non-zero) is reported not-found and never recalled or fabricated."""
    ep, audit = _start(frm, tmp_path, nearline=False)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode != 0
    assert not os.path.exists(out) or open(out, "rb").read() != TAPE_BYTES
    assert not [v for v in _audit(audit) if v[0] == "recall"], _audit(audit)


def test_stub_adapter_recalls_from_local_tape(frm, tmp_path):
    """The stub adapter recalls an offline object from a local tape directory
    with no operator stage command."""
    ep, _ = _start(frm, tmp_path, adapter="stub")
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == TAPE_BYTES
