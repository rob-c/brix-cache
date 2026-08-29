"""xrdcp --continue byte-offset resume (parity-audit §7.6).

--continue is the operator's opt-OUT of the atomic temp+rename discipline:
the destination is written in place, an existing partial is resumed at its
size, and a FAILED transfer leaves the partial for the next --continue.  A
COMPLETED file that then fails --cksum is still dropped — fail-closed applies
to integrity verdicts, only in-progress partials are protected.

  * success   — a staged partial resumes to a byte-exact whole; a missing
                destination is simply a fresh (direct-write) copy; equal
                sizes are a no-op
  * error     — a local file LARGER than the source is refused (exit 50) and
                left untouched; conflicting flags are usage errors
  * security  — a poisoned partial + --cksum of the true content completes,
                fails the digest, and the destination is REMOVED (a corrupt
                resume cannot plant a full-size file)

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_continue.py -v
"""

import hashlib
import os
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

# xdist_group: this module stages its fixture data under the SHARED
# DATA_ROOT in a module-scoped fixture.  Ungrouped cells spread across
# workers under --dist loadgroup, so each worker runs its own copy of
# that fixture and the first teardown deletes the file out from under
# the workers still using it ("NotFound").  One group == one worker.
pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
    pytest.mark.xdist_group("xrdcp-continue"),
]

CONTENT = bytes((i * 31 + 7) % 251 for i in range(6 * 1024 * 1024))
NAME = "continue-src.bin"


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, NAME), "wb") as f:
        f.write(CONTENT)
    yield
    try:
        os.remove(os.path.join(DATA_ROOT, NAME))
    except FileNotFoundError:
        pass


def _url():
    return f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{NAME}"


def _run(args, timeout=90):
    return subprocess.run([XRDCP] + args, capture_output=True, text=True,
                          timeout=timeout)


class TestContinueSuccess:

    def test_partial_resumes_byte_exact(self, tmp_path):
        """(success) a 2 MiB partial resumes into the full 6 MiB, byte-exact —
        and the head is NOT re-downloaded (mtime of the head bytes is
        irrelevant; only the equality proof matters)."""
        dst = tmp_path / "out.bin"
        dst.write_bytes(CONTENT[:2 * 1024 * 1024])
        res = _run(["--continue", _url(), str(dst)])
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_fresh_destination_full_copy(self, tmp_path):
        """(success) no existing partial: --continue is just a direct-write
        full copy."""
        dst = tmp_path / "out.bin"
        res = _run(["--continue", _url(), str(dst)])
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_equal_size_noop(self, tmp_path):
        """(success) destination already complete: exit 0, bytes untouched."""
        dst = tmp_path / "out.bin"
        dst.write_bytes(CONTENT)
        res = _run(["--continue", _url(), str(dst)])
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT


class TestContinueErrors:

    def test_local_larger_than_source_refused(self, tmp_path):
        """(error) an oversized local file is a usage error and is left
        exactly as it was."""
        dst = tmp_path / "out.bin"
        blob = CONTENT + b"tail-beyond-source"
        dst.write_bytes(blob)
        res = _run(["--continue", _url(), str(dst)])
        assert res.returncode == 50, (res.returncode, res.stderr)
        assert "larger than the source" in res.stderr
        assert dst.read_bytes() == blob

    @pytest.mark.parametrize("combo", [
        ["--continue", "-f"],
        ["--continue", "--pgrw"],
        ["--continue", "--resume", "--from", "/dev/null"],
    ])
    def test_conflicting_flags_refused(self, combo, tmp_path):
        """(error) truncating / re-framing / other-resume flags are rejected
        before any bytes move."""
        res = _run(combo + [_url(), str(tmp_path / "out.bin")], timeout=30)
        assert res.returncode == 50, (combo, res.returncode, res.stderr)


class TestContinueHostile:

    def test_poisoned_partial_fails_closed(self, tmp_path):
        """(security-neg) a partial whose head bytes are WRONG completes the
        tail, fails the whole-file --cksum, and the destination is removed —
        a corrupt resume cannot plant a full-size file."""
        dst = tmp_path / "out.bin"
        poisoned = bytes(len(CONTENT[:1024 * 1024]))          # zeroed head
        dst.write_bytes(poisoned)
        digest = hashlib.md5(CONTENT).hexdigest()
        res = _run(["-s", "--continue", "--cksum", f"md5:{digest}",
                    _url(), str(dst)])
        assert res.returncode != 0
        assert not dst.exists(), "corrupt completed file survived --cksum"
