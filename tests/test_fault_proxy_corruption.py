"""
test_fault_proxy_corruption.py — this repo's client tools vs a REAL server,
through a network that silently CORRUPTS bytes on the wire.

WHAT: splices the in-repo TCP fault proxy (brix-fault-proxy) between THIS
      codebase's xrdcp and a real server (official `xrootd` and this repo's
      nginx), turns on in-band payload corruption (`corrupt` — a random bit-flip
      in a fraction of forwarded bytes, i.e. an on-path MITM / a flaky NIC past
      the TCP checksum), and asserts the tool DETECTS the tamper rather than
      handing back corrupt bytes as a "successful" copy.

WHY:  a checksum below userland (TCP, the NIC) is not a guarantee — a bit can
      still flip on the path, and a tool that trusts the wire will silently write
      the wrong file.  These tests pin the two integrity paths that must catch it:
        (a) pgread per-page CRC32c   — `xrdcp --pgrw`   (INVARIANT #1)
        (b) end-to-end query-checksum — `xrdcp --verify` (server must support it)
      The one outcome that must NEVER happen: exit 0 with corrupt bytes on disk.

      (Deliberately NOT asserted here: a plain `kXR_read` copy carries no
      integrity and WILL silently return corrupt bytes — which is precisely why
      the integrity flags above exist.  The FUSE mount reads via plain kXR_read
      too; it is a resilience surface, not an integrity one.)

HOW:  client  ->  brix-fault-proxy (corrupt down)  ->  real server

Skips cleanly when the official `xrootd`, the repo nginx, or the proxy is absent.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_fault_proxy_corruption.py -v
"""
import hashlib
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "resilience"))
from resilience.servers import (  # noqa: E402
    XrootdAnon, NginxAnon, FaultProxy, seed_file, XRDCP, FAULT_PROXY,
)

XROOTD = shutil.which("xrootd")
NGINX = os.environ.get("RESIL_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

pytestmark = pytest.mark.timeout(300)

FILE_MB = 4
# Bit-flip rate for the detection legs.  Over a 4 MiB file this is ~80k corrupted
# bytes: the first pgread page is hit with certainty, so detection is not flaky.
CORRUPT_PCT = 2.0

# Any of these in the tool's stderr proves it caught the wire tamper and REFUSED
# the data — whether the poisoned byte landed in a pgread page (CRC32c), the
# kXR_status trailer, the checksum comparison, or the login/framing (a desync
# surfaces as a decode/protocol error or a read timeout).  Which layer catches it
# is secondary; that it is caught, not silently returned, is the guarantee.
_DETECT_MARKERS = (
    "crc", "pgread", "mismatch", "checksum", "cksum", "header",
    "handshake", "status", "invalid", "corrupt", "decode", "protocol",
    "time",   # "read timed out" / "timeout" — framing desync from a flipped header
)

_PROXY_MISSING = not os.path.isfile(FAULT_PROXY)


def _env():
    e = dict(os.environ)
    e.pop("LD_LIBRARY_PATH", None)   # keep the system XRootD libs clean (see servers.gsi_env)
    return e


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _xrdcp(url, out, *extra, timeout=120):
    if os.path.exists(out):
        os.remove(out)
    r = subprocess.run([XRDCP, "-f", *extra, url, out],
                       env=_env(), capture_output=True, timeout=timeout)
    return r.returncode, r.stderr.decode(errors="replace")


def _silent_corruption(rc, out, ref):
    """The failure we are hunting: the tool reports SUCCESS (rc 0) yet the bytes on
    disk do not match the source — corruption the networking stack slipped past
    userland and the tool blessed as a good copy."""
    return rc == 0 and os.path.exists(out) and _md5(out) != ref


def _detected(err):
    low = err.lower()
    return any(m in low for m in _DETECT_MARKERS)


# --- links: a real server with the corrupting proxy in front ------------------

@pytest.fixture(scope="module")
def _xrootd_corrupt_link():
    if not XROOTD or _PROXY_MISSING:
        pytest.skip("need official `xrootd` on PATH + built brix-fault-proxy")
    with XrootdAnon() as srv:
        src = seed_file(srv.data, "/big.bin", FILE_MB * 1024 * 1024)
        ref = _md5(src)
        with FaultProxy(srv.port) as fp:
            yield fp, f"root://127.0.0.1:{fp.listen}//big.bin", ref


@pytest.fixture(scope="module")
def _nginx_corrupt_link():
    if not os.path.isfile(NGINX) or _PROXY_MISSING:
        pytest.skip("need repo nginx (objs/nginx) + built brix-fault-proxy")
    with NginxAnon() as srv:
        src = seed_file(srv.data, "/big.bin", FILE_MB * 1024 * 1024)
        ref = _md5(src)
        with FaultProxy(srv.port) as fp:
            yield fp, f"root://127.0.0.1:{fp.listen}//big.bin", ref


@pytest.fixture
def xlink(_xrootd_corrupt_link):
    """Per-test view of the xrootd link with the fault levers reset either side."""
    fp, url, ref = _xrootd_corrupt_link
    fp.clear()
    yield fp, url, ref
    fp.clear()


@pytest.fixture
def nlink(_nginx_corrupt_link):
    fp, url, ref = _nginx_corrupt_link
    fp.clear()
    yield fp, url, ref
    fp.clear()


# --- tests --------------------------------------------------------------------

def test_clean_link_baseline_passes(xlink, tmp_path):
    """SUCCESS: with the link healthy, both a plain read and a pgread/CRC32c read
    return byte-exact — the integrity check does not false-positive on good data
    (otherwise every 'detection' below would be meaningless)."""
    fp, url, ref = xlink
    out = str(tmp_path / "clean.bin")
    for extra in ([], ["--pgrw"]):
        rc, err = _xrdcp(url, out, *extra)
        assert rc == 0, f"clean transfer failed (extra={extra}) rc={rc}: {err[-300:]}"
        assert _md5(out) == ref, f"clean transfer not byte-exact (extra={extra})"


def test_pgread_crc_detects_wire_corruption(xlink, tmp_path):
    """ERROR / INVARIANT #1: a pgread (`--pgrw`) copy over a link that flips
    payload bits detects the tamper (per-page CRC32c) and FAILS loudly — it never
    returns the corrupt bytes as a success."""
    fp, url, ref = xlink
    fp.set_corrupt(CORRUPT_PCT, "down")
    out = str(tmp_path / "pg.bin")
    rc, err = _xrdcp(url, out, "--pgrw")
    assert rc != 0, f"pgread accepted corrupt data (rc=0): {err[-400:]}"
    assert not _silent_corruption(rc, out, ref)
    assert _detected(err), f"corruption not surfaced in stderr: {err[-400:]}"


def test_verify_endtoend_checksum_detects_corruption(nlink, tmp_path):
    """ERROR: `xrdcp --verify` checksums the received bytes and compares against
    the server's query-checksum (nginx supports it); over a corrupting link either
    the two disagree (adler32 mismatch) or a flipped framing byte desyncs the read
    first — either way the copy FAILS.  The end-to-end guarantee against on-wire
    tamper for the plain-read path: corruption is never blessed as a good copy."""
    fp, url, ref = nlink
    fp.set_corrupt(CORRUPT_PCT, "down")
    out = str(tmp_path / "v.bin")
    rc, err = _xrdcp(url, out, "--verify")
    assert rc != 0, f"--verify accepted corrupt data (rc=0): {err[-400:]}"
    assert not _silent_corruption(rc, out, ref)
    assert _detected(err), f"checksum mismatch not surfaced in stderr: {err[-400:]}"


@pytest.mark.parametrize("pct", [0.5, 2.0, 5.0])
def test_pgread_never_silently_returns_corruption(xlink, tmp_path, pct):
    """SECURITY-NEG: across a range of MITM bit-flip rates, the integrity read
    NEVER reports success while holding corrupt bytes.  The tamper must surface as
    a non-zero exit — a CRC mismatch, or a framing/connection error — but never as
    a silent, wrong-but-'successful' file.  This is the core promise."""
    fp, url, ref = xlink
    fp.set_corrupt(pct, "down")
    out = str(tmp_path / f"neg_{pct}.bin")
    rc, err = _xrdcp(url, out, "--pgrw")
    assert not _silent_corruption(rc, out, ref), (
        f"SILENT CORRUPTION at {pct}% (rc={rc}): a wrong file was reported as a "
        f"good copy — the tool shat the bed. stderr: {err[-300:]}")


def test_corrupt_request_path_never_silently_corrupts(xlink, tmp_path):
    """DIRECTIONAL: corrupt only the UP (client->server) path — the request /
    handshake bytes.  The download must come back byte-exact OR the copy must
    fail; a poisoned request must never yield a wrong file blessed as success."""
    fp, url, ref = xlink
    fp.set_corrupt(3.0, "up")
    out = str(tmp_path / "up.bin")
    rc, err = _xrdcp(url, out, "--pgrw")
    assert not _silent_corruption(rc, out, ref), (
        f"SILENT CORRUPTION on the request path (rc={rc}): {err[-300:]}")
