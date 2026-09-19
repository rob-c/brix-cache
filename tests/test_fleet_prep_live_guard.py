"""Session artifacts are never replaced underneath a fleet that is already up.

A fleet member loads its certificates, key and JWKS ONCE, at startup.  Nothing
re-reads them, so replacing the files on disk mid-session does not fail — it
splits the world in two: the servers keep presenting the material they booted
with, while every client reads the new material off disk.  Each side is
internally consistent, and each side's error message blames the other ("unable
to get local issuer certificate", "certificate verification failed").

``start_all()`` is where the two meet.  It runs ``fleet_prep.prepare()``
unconditionally, and ``_launch_nginx`` treats "a master already owns this
prefix" as success — so a second ``start-all`` re-provisions the artifacts and
then deliberately leaves the servers holding the old ones.  Observed
2026-09-19: a fleet launched at 08:46:34 against a CA replaced at 08:51:28,
which silently broke every native-client and credential-bridge test for the
rest of the session.

Two guards, pinned here:

  * ``start_all`` skips provisioning while the ``main`` master is alive
    (``restart`` is the way to rebuild both together);
  * ``prep_steps.regenerate_pki`` blitzes only an INCOMPLETE tree, so the
    direct callers that bypass ``start_all`` (``lib_py.dedicated``,
    ``cmdscripts.pblock_live``) cannot replace a live fleet's CA either.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import fleet_prep
from cmdscripts import manage_test_servers as mts


# --------------------------------------------------------------------------
# start-all: provision only when no fleet holds the artifacts
# --------------------------------------------------------------------------

class _StubLauncher:
    """Records the specs it was asked to start; starts nothing."""

    def __init__(self):
        self.started = []

    def start_registered(self, specs):
        self.started.append(list(specs))
        return {}


@pytest.fixture
def start_all_env(tmp_path, monkeypatch):
    """`start_all()` with every side effect but the guard decision stubbed out.

    Returns (calls, launcher): `calls` records each `prepare()` invocation.
    """
    calls = []
    launcher = _StubLauncher()
    monkeypatch.setattr(fleet_prep, "prepare", lambda *a, **k: calls.append("prepare"))
    monkeypatch.setattr(mts, "_register", lambda: [])
    monkeypatch.setattr(mts, "_launcher", lambda: launcher)
    # `start_all` does `from settings import FLEET_READY` at CALL time, so
    # rebinding the attribute on the module redirects the marker; the value is
    # computed at settings-import time and would not follow $TEST_ROOT.
    import settings
    monkeypatch.setattr(settings, "FLEET_READY", str(tmp_path / "fleet.ready"))
    return calls, launcher


def test_no_live_master_provisions_the_artifacts_as_before(start_all_env, monkeypatch):
    """success: the ordinary cold start still generates the session artifacts."""
    calls, launcher = start_all_env
    monkeypatch.setattr(mts, "_fleet_master_alive", lambda: False)

    assert mts.start_all() == 0
    assert calls == ["prepare"]
    assert launcher.started == [[]], "the launcher must still run"


def test_a_live_master_keeps_the_artifacts_it_booted_with(start_all_env, monkeypatch):
    """security-negative: a running fleet's CA is never replaced underneath it.

    This is the whole point of the guard.  Regenerating here mints a new CA
    while every live server keeps serving the old leaf, and the damage shows up
    only later, as TLS/GSI failures that name neither prep nor start-all.
    """
    calls, launcher = start_all_env
    monkeypatch.setattr(mts, "_fleet_master_alive", lambda: True)

    assert mts.start_all() == 0
    assert calls == [], "prepare() must not run under a live fleet"
    assert launcher.started == [[]], "missing instances must still be launched"


# --------------------------------------------------------------------------
# _fleet_master_alive: only OUR master counts
# --------------------------------------------------------------------------

@pytest.fixture
def registry(tmp_path, monkeypatch):
    """Point settings.REGISTRY_ROOT at a private tree; return main's pidfile."""
    import settings
    root = tmp_path / "registry"
    pidfile = root / "main" / "logs" / "nginx.pid"
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "REGISTRY_ROOT", str(root))
    return pidfile


def test_a_missing_pidfile_is_not_a_live_master(registry):
    """success: nothing recorded, nothing running — provisioning may proceed."""
    assert mts._fleet_master_alive() is False


def test_a_dead_pid_is_not_a_live_master(registry):
    """error path: a pidfile left behind by a crashed master must not block
    provisioning, or a lane could never recover its PKI after a crash."""
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    registry.write_text(f"{dead.pid}\n", encoding="utf-8")

    assert mts._fleet_master_alive() is False


def test_a_foreign_process_on_a_recycled_pid_is_not_the_master(registry):
    """security-negative: a pid that has been recycled by an unrelated process
    must NOT read as a live fleet.  Believing it would skip provisioning for a
    fleet that is not there, leaving the lane with no PKI at all — so the check
    matches the registry prefix in the process's argv, not just liveness."""
    registry.write_text(f"{os.getpid()}\n", encoding="utf-8")

    assert mts._fleet_master_alive() is False, \
        "this pytest process does not serve the fleet prefix"


# --------------------------------------------------------------------------
# regenerate_pki: blitz only an incomplete tree
# --------------------------------------------------------------------------

#: Run in a child so TEST_ROOT (read by settings at import time, and therefore
#: by the generator's CA_CERT/CA_KEY/... constants) points at the private tree.
#: One child does all three phases: a blitz mints a 4096-bit CA, and paying for
#: that three times over would not buy any more coverage.
_PHASES = """
import hashlib, os, sys
from pathlib import Path
from brix_suite.prep_steps import regenerate_pki
from brix_suite.settings import CA_CERT, CA_KEY, PKI_DIR
import json

def digest():
    return hashlib.sha256(Path(CA_CERT).read_bytes()).hexdigest()

env = dict(os.environ)
regenerate_pki(PKI_DIR, env)          # cold: nothing on disk yet
first = digest()
regenerate_pki(PKI_DIR, env)          # a complete tree must be left alone
again = digest()
os.unlink(CA_KEY)                     # an orphan CA cannot sign: incomplete
regenerate_pki(PKI_DIR, env)
rebuilt = digest()
print(json.dumps({"first": first, "again": again, "rebuilt": rebuilt}))
"""


@pytest.fixture(scope="module")
def pki_phases(tmp_path_factory):
    """The CA digest after a cold build, a re-prep, and a repair."""
    if not any(Path(d, "openssl").exists() for d in os.get_exec_path()):
        pytest.skip("openssl not installed")
    root = tmp_path_factory.mktemp("lane")
    tests = Path(__file__).resolve().parent
    env = dict(os.environ, PYTHONPATH=str(tests), TEST_ROOT=str(root))
    env.pop("PKI_DIR", None)
    child = subprocess.run([sys.executable, "-c", _PHASES], cwd=str(tests),
                           env=env, capture_output=True, text=True, timeout=300)
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout.strip().splitlines()[-1])


def test_a_cold_tree_gets_a_freshly_minted_ca(pki_phases):
    """success: with nothing on disk, prep still generates the whole PKI."""
    assert len(pki_phases["first"]) == 64


def test_a_second_prep_does_not_replace_a_complete_ca(pki_phases):
    """security-negative: the byte-for-byte CA a standing fleet was started
    against must survive a re-prep — this is the file whose replacement split
    the fleet from its clients."""
    assert pki_phases["again"] == pki_phases["first"]


def test_an_incomplete_pki_is_still_rebuilt(pki_phases):
    """error path: a CA certificate whose private key is gone can sign nothing,
    so reuse would leave every later proxy mint failing.  Regenerate it."""
    assert pki_phases["rebuilt"] != pki_phases["first"]
