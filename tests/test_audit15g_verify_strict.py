"""
test_audit15g_verify_strict.py — what `xrdcp --verify` reports when it did not
actually verify anything (audit §C carry-over row "`--verify` strict mode").

The 2026-08-04 pass measured the policy on the corruption bench and recorded the
conclusion: `--verify` is FAIL-OPEN — a checksum verdict that comes back
UNVERIFIED (as opposed to WRONG) prints a warning, is cleared out of the status,
and the transfer exits 0 with the file kept (`download_reconcile_cksum`,
client/lib/xfer/copy_local.c:271-287).  "A strict mode for `--verify` (treat
UNVERIFIED as a failure) is the obvious follow-up and is **not** implemented."

That measurement needed a fault proxy and a 5%-flaky trigger, so it could only
assert a union of outcomes.  This file pins the same policy deterministically,
from the two directions that need no corruption at all:

  * a `--cksum` spec the client cannot parse is a USAGE error, and a usage error
    is UNVERIFIED — so a typo in an automation flag silently turns verification
    off and the exit status still says 0;
  * a stdio destination has no file to digest, so cksum_verify returns OK
    outright (copy_cksum_verify.c:181-188) — piping a "verified" download
    verifies nothing, and this one does not even warn in the status.

Neither is a mistake in isolation: deleting a byte-perfect download because a
control-plane query hiccupped would be the inverse footgun, and there is
genuinely nothing to digest on a pipe.  What makes them worth pinning is that
BOTH are indistinguishable from a real verification at the only place an
automated caller looks — the exit status.  The two success/mismatch controls
below are what make that a statement about the verdict and not about checksums:
a definitely-WRONG digest is refused, non-zero, and the destination is dropped.

WHEN A STRICT MODE LANDS, this file is where it is specified: the two pins
invert (non-zero exit, and for the download case no file left behind), and the
two controls must not move at all.

Cases:
  * success      — `--verify` against a server that answers: rc 0, exact bytes,
                   and the client says whose digest it matched
  * sec-negative — a digest that is definitely WRONG: rc != 0 AND the
                   destination is removed, not left as a half-trusted file
  * pin          — an unparseable `--cksum` type: rc 0, file kept, verification
                   silently skipped
  * pin          — a stdio destination: rc 0, bytes on stdout, verification
                   skipped without even the "NOT verified" note
"""

import hashlib
import os
import shutil
import subprocess

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-verify")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")

SEED = b"audit15g-verify-strict-payload\n" * 128
REMOTE = "obj.bin"


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp build failed")


@pytest.fixture
def plane(lifecycle, _client_built, tmp_path):
    """(url, data_dir) for a stock writable anonymous posix plane.

    Deliberately the shared template and nothing special: the subject of this
    file is the client's verdict policy, and a server that answers kXR_Qcksum
    normally is what makes "not verified" a statement about the client."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / REMOTE).write_bytes(SEED)
    os.chmod(data / REMOTE, 0o644)
    os.chmod(data, 0o777)

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15g-verify",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="audit-15g `xrdcp --verify` verdict policy"))
    return f"root://{HOST}:{endpoint.port}/{REMOTE}", data


def _xrdcp(*args, timeout=60):
    return subprocess.run([XRDCP, *args], capture_output=True, timeout=timeout)


def _adler32(blob):
    """The digest the server will report — computed the way the client does, so
    the "wrong" digest below is wrong by construction rather than by luck."""
    import zlib
    return f"{zlib.adler32(blob) & 0xffffffff:08x}"


def test_verify_against_a_server_that_answers_reports_the_match(plane, tmp_path):
    """success: the control.  Establishes that this plane answers kXR_Qcksum,
    that the digests agree, and that the client says so — without which every
    "not verified" below could just mean "checksums do not work here"."""
    url, _data = plane
    dst = tmp_path / "ok.bin"

    done = _xrdcp("--verify", url, str(dst))

    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert dst.read_bytes() == SEED
    assert b"OK (matches server)" in done.stdout, done.stdout[-400:]
    assert _adler32(SEED).encode() in done.stdout.lower(), done.stdout[-400:]


def test_a_definitely_wrong_digest_fails_and_drops_the_destination(plane, tmp_path):
    """security-negative: the yardstick for both pins.  A digest the client can
    prove WRONG is a data-integrity failure — non-retryable, non-zero, and the
    destination must not survive it, because a file left on disk after a failed
    verification is a file some later step will treat as good."""
    url, _data = plane
    dst = tmp_path / "wrong.bin"
    wrong = "deadbeef"
    assert wrong != _adler32(SEED)

    # Two argv entries, not `--cksum=...`: this CLI takes the value as the next
    # argument and rejects the equals form as an unknown option (rc 50).
    done = _xrdcp("--cksum", f"adler32:{wrong}", url, str(dst))

    assert done.returncode != 0, done.stdout.decode(errors="replace")
    assert b"mismatch" in done.stderr.lower(), done.stderr[-400:]
    assert not dst.exists(), "a file that failed verification was left behind"


def test_an_unparseable_cksum_type_silently_skips_verification(plane, tmp_path):
    """DEFECT PIN — the `--verify` strict-mode gap, usage half.  `sha3-512` is
    not a type this client implements, so the spec fails to parse; that is a
    usage error, a usage error is UNVERIFIED, and UNVERIFIED is warn-and-clear.
    The operator asked for a checksum, got none, and the exit status is
    identical to the verified transfer in the first test.

    The warning is on stderr, which no `if xrdcp ...; then` reads.

    INVERT WHEN A STRICT MODE LANDS: returncode != 0, and the destination is
    gone the way the mismatch case above leaves it."""
    url, _data = plane
    dst = tmp_path / "typo.bin"

    done = _xrdcp("--cksum", "sha3-512:source", url, str(dst))

    # INVERT WHEN FIXED — both.
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert dst.read_bytes() == SEED, "the bytes are fine — that is the point"
    assert b"NOT verified" in done.stderr, done.stderr[-400:]
    assert b"unsupported --cksum type" in done.stderr, done.stderr[-400:]


def test_a_stdio_destination_reports_success_having_verified_nothing(plane):
    """DEFECT PIN — the `--verify` strict-mode gap, stdio half, and the quieter
    of the two: cksum_verify returns OK (not UNVERIFIED) for a stdio endpoint,
    so `download_reconcile_cksum` has nothing to warn about and the status is
    clean.  `xrdcp --verify src - | consumer` is the shape of every streaming
    pipeline, and it carries a verification flag that cannot do anything.

    INVERT WHEN A STRICT MODE LANDS: `--verify` with no local file to digest is
    a usage refusal (non-zero, no bytes moved) rather than a skipped check."""
    url, _data = plane

    done = _xrdcp("--verify", url, "-")

    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert hashlib.sha256(done.stdout).hexdigest() == \
        hashlib.sha256(SEED).hexdigest(), "the pipe did not get the file"
    # INVERT WHEN FIXED: this is the whole finding — the flag was accepted, the
    # transfer reported success, and the check was skipped.
    assert b"skipped for stdin/stdout" in done.stderr, done.stderr[-400:]
    assert b"NOT verified" not in done.stderr, \
        "the stdio skip now warns like an UNVERIFIED query — narrow this pin"
