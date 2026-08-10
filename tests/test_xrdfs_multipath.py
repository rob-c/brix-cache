"""xrdfs multi-path operands for stat / rm / cat.

Feature-parity audit §9.2 verified bug: ``xrdfs stat a b`` (and rm/cat) parsed
every non-flag argument into ONE variable, so only the LAST path was acted on
— silently.  Every operand is now processed independently (POSIX semantics): a
failing path is reported on stderr and the remaining operands still run; the
exit code is the first failure's.

Coverage (the change-class trio, per verb where it differs):
  * success      — stat prints a block per path; cat concatenates in operand
                   order byte-exact; rm removes every operand.
  * error        — a missing path mid-list fails the exit code but the
                   surviving operands are still processed (stat prints them,
                   cat streams them, rm deletes them).
  * security-neg — ``rm -r / sub`` : the export-root refusal holds for the
                   "/" operand (nothing under root is touched by it) while the
                   sibling operand is still processed independently — mixing a
                   refused operand into a list neither aborts the valid ones
                   nor weakens the refusal.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_xrdfs_multipath.py -v
"""

import json
import os
import shutil
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrdfs-multipath")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

PAYLOAD_A = b"alpha-payload-0123456789\n"
PAYLOAD_B = b"beta-payload\n"


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs build failed")


@pytest.fixture()
def srv(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    (data / "sub").mkdir(parents=True)
    (data / "a.txt").write_bytes(PAYLOAD_A)
    (data / "b.txt").write_bytes(PAYLOAD_B)
    (data / "keep.txt").write_bytes(b"survivor\n")
    (data / "sub" / "inner.txt").write_bytes(b"inner\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdfs-multipath",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrdfs multi-path operands against a writable anon root server"))
    return {"port": ep.port, "data": data}


def _run(srv, *args):
    url = f"root://{HOST}:{srv['port']}"
    return subprocess.run([XRDFS, url, *args], capture_output=True, timeout=30)


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_stat_two_paths_prints_both(srv):
    """(success) stat a b prints one metadata block PER operand — the last-path
    -only bug printed exactly one."""
    p = _run(srv, "stat", "/a.txt", "/b.txt")
    out = p.stdout.decode()
    assert p.returncode == 0, p.stderr
    assert "Path:   /a.txt" in out, out
    assert "Path:   /b.txt" in out, out


def test_stat_json_two_paths_is_ndjson(srv):
    """(success) stat -j a b emits one parseable JSON object per operand."""
    p = _run(srv, "stat", "-j", "/a.txt", "/b.txt")
    assert p.returncode == 0, p.stderr
    lines = [ln for ln in p.stdout.decode().splitlines() if ln.strip()]
    assert len(lines) == 2, p.stdout
    paths = {json.loads(ln)["path"] for ln in lines}
    assert paths == {"/a.txt", "/b.txt"}, paths


def test_cat_concatenates_in_operand_order(srv):
    """(success) cat a b streams both files back-to-back, byte-exact and in
    operand order (POSIX cat)."""
    p = _run(srv, "cat", "/a.txt", "/b.txt")
    assert p.returncode == 0, p.stderr
    assert p.stdout == PAYLOAD_A + PAYLOAD_B, p.stdout


def test_rm_removes_every_operand(srv):
    """(success) rm a b deletes BOTH operands — the last-path-only bug left
    the first in place while reporting success."""
    p = _run(srv, "rm", "/a.txt", "/b.txt")
    assert p.returncode == 0, p.stderr
    assert not (srv["data"] / "a.txt").exists(), "first operand survived rm"
    assert not (srv["data"] / "b.txt").exists(), "second operand survived rm"


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

def test_stat_missing_middle_path_reports_and_continues(srv):
    """(error) a missing operand fails the exit code; operands before AND
    after it still print."""
    p = _run(srv, "stat", "/a.txt", "/does-not-exist", "/b.txt")
    out = p.stdout.decode()
    assert p.returncode != 0, "missing operand must fail the exit code"
    assert "Path:   /a.txt" in out, out
    assert "Path:   /b.txt" in out, out
    assert b"does-not-exist" in p.stderr, p.stderr


def test_cat_missing_first_path_still_streams_rest(srv):
    """(error) cat missing a → nonzero exit, stderr names the missing path,
    stdout carries the surviving operand's bytes exactly."""
    p = _run(srv, "cat", "/does-not-exist", "/a.txt")
    assert p.returncode != 0
    assert p.stdout == PAYLOAD_A, p.stdout
    assert b"does-not-exist" in p.stderr, p.stderr


def test_rm_missing_path_still_removes_rest(srv):
    """(error) rm missing b → nonzero exit, but the valid operand is gone."""
    p = _run(srv, "rm", "/does-not-exist", "/b.txt")
    assert p.returncode != 0
    assert not (srv["data"] / "b.txt").exists(), "valid operand survived rm"


# --------------------------------------------------------------------------- #
# security-neg
# --------------------------------------------------------------------------- #

def test_rm_r_root_refusal_holds_among_operands(srv):
    """(security-neg) rm -r / sub — the export-root refusal fires for "/"
    (non-operand files survive) and fails the exit code; the sibling operand
    is still processed independently."""
    p = _run(srv, "rm", "-r", "/", "/sub")
    assert p.returncode != 0, "export-root operand must fail the exit code"
    assert b"refusing" in p.stderr, p.stderr
    assert (srv["data"] / "keep.txt").exists(), \
        "export-root refusal was bypassed: non-operand file deleted"
    assert not (srv["data"] / "sub").exists(), \
        "valid sibling operand was not processed after the refusal"
