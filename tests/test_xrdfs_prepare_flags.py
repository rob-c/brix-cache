"""xrdfs prepare stock flag semantics — wire-truth via ``--capture``.

Parity audit §7.12 named prepare ``-p``/``-a`` missing; auditing the fix
against the installed stock xrdfs 5.6.9 exposed something worse: BriX mapped
``-c`` to kXR_cancel, but stock ``-c`` means CO-LOCATE (abort is ``-a``) — a
stock script asking to co-locate would silently CANCEL its own stage request.

Now (stock semantics): -s stage, -w wmode, -c kXR_coloc, -a kXR_cancel,
-f fresh, -e evict (optionX), -p <0-3> request priority. The tests decode the
actual ClientPrepareRequest bytes from the client's own ``--capture`` bundle
(magic "XRDCAP1\\n", 'M' meta / 'F' frame records; a frame's wire bytes are
the verbatim 24-byte request header + body), so the assertion is the wire
truth, not CLI output.

Coverage (the change-class trio):
  * success      — -s -p 2 emits options=kXR_stage prty=2; -a emits
                   kXR_cancel; -w/-f compose.
  * error        — -p out of range (4) or non-numeric is refused usage-style
                   (exit 50), and nothing reaches the wire.
  * security-neg — -c emits kXR_coloc and NOT kXR_cancel: the co-locate
                   spelling can never silently abort a request again.

Server: a per-test writable anon posix root:// server (the request must be
accepted end-to-end for the capture to carry it).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_xrdfs_prepare_flags.py -v
"""

import os
import shutil
import struct
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrdfs-prepflags")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

kXR_prepare = 3021
kXR_cancel, kXR_notify, kXR_stage, kXR_wmode = 0x01, 0x02, 0x08, 0x10
kXR_coloc, kXR_fresh = 0x20, 0x40


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
    data.mkdir()
    (data / "f.txt").write_bytes(b"prepare-me\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdfs-prepflags",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrdfs prepare stock flag semantics (wire capture)"))
    return ep.port


def _prepare_frames(capture_path):
    """Parse an .xrdcap bundle; yield the wire bytes of every kXR_prepare
    REQUEST frame (header+body verbatim)."""
    blob = open(capture_path, "rb").read()
    assert blob[:8] == b"XRDCAP1\n", "not an xrdcap bundle"
    cursor, frames = 8, []
    while cursor < len(blob):
        tag = blob[cursor:cursor + 1]
        cursor += 1
        if tag == b"M":
            klen = blob[cursor]
            cursor += 1 + klen
            vlen = struct.unpack(">H", blob[cursor:cursor + 2])[0]
            cursor += 2 + vlen
        elif tag == b"F":
            _dir, is_req = blob[cursor], blob[cursor + 1]
            code = struct.unpack(">H", blob[cursor + 4:cursor + 6])[0]
            wirelen = struct.unpack(">I", blob[cursor + 6:cursor + 10])[0]
            wire = blob[cursor + 10:cursor + 10 + wirelen]
            cursor += 10 + wirelen
            if is_req and code == kXR_prepare:
                frames.append(wire)
        else:
            break
    return frames


def _run_prepare(srv, tmp_path, *args):
    """Run xrdfs prepare under --capture; returns (rc, options, prty) with
    options/prty None when no prepare frame reached the wire."""
    cap = str(tmp_path / "prep.xrdcap")
    url = f"root://{HOST}:{srv}"
    proc = subprocess.run([XRDFS, "--capture", cap, url, "prepare", *args],
                          capture_output=True, text=True, timeout=30)
    frames = _prepare_frames(cap) if os.path.exists(cap) else []
    if not frames:
        return proc.returncode, None, None
    # ClientPrepareRequest header: sid(2) reqid(2) options(1) prty(1) ...
    wire = frames[-1]
    return proc.returncode, wire[4], wire[5]


def test_stage_with_priority(srv, tmp_path):
    """(success) -s -p 2 puts kXR_stage in options and 2 in prty."""
    rc, options, prty = _run_prepare(srv, tmp_path, "-s", "-p", "2", "/f.txt")
    assert rc == 0, f"prepare failed rc={rc}"
    assert options is not None, "no prepare frame captured"
    assert options & kXR_stage, f"kXR_stage missing: options={options:#x}"
    assert prty == 2, f"priority not carried: prty={prty}"


def test_abort_spelling_sends_cancel(srv, tmp_path):
    """(success) -a (the stock abort spelling) sends kXR_cancel."""
    rc, options, _prty = _run_prepare(srv, tmp_path, "-a", "/f.txt")
    assert options is not None, "no prepare frame captured"
    assert options & kXR_cancel, f"-a did not send kXR_cancel: {options:#x}"


def test_wmode_fresh_compose(srv, tmp_path):
    """(success) -s -w -f compose into one options byte, default prty 0."""
    rc, options, prty = _run_prepare(srv, tmp_path, "-s", "-w", "-f", "/f.txt")
    assert options is not None
    for bit, name in ((kXR_stage, "stage"), (kXR_wmode, "wmode"),
                      (kXR_fresh, "fresh")):
        assert options & bit, f"{name} missing: options={options:#x}"
    assert prty == 0, f"default priority not 0: {prty}"


def test_priority_out_of_range_refused(srv, tmp_path):
    """(error) -p 4 and -p x are usage errors (exit 50, stock range 0-3) and
    nothing reaches the wire."""
    for bad in ("4", "x", "-1"):
        rc, options, _p = _run_prepare(srv, tmp_path, "-s", "-p", bad, "/f.txt")
        assert rc == 50, f"-p {bad}: rc={rc} (want usage 50)"
        assert options is None, f"-p {bad}: request reached the wire anyway"


def test_colocate_is_not_cancel(srv, tmp_path):
    """(security-neg) -c sends kXR_coloc and MUST NOT send kXR_cancel — the
    old mapping made a stock co-locate request silently abort the stage."""
    rc, options, _prty = _run_prepare(srv, tmp_path, "-s", "-c", "/f.txt")
    assert options is not None, "no prepare frame captured"
    assert options & kXR_coloc, f"-c did not send kXR_coloc: {options:#x}"
    assert not (options & kXR_cancel), \
        f"-c leaked kXR_cancel — stock co-locate would abort: {options:#x}"
