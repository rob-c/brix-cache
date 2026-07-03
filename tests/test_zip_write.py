"""
Phase-42 W3 (write) — xrdcp ZIP writer end-to-end.

Exercises `xrdcp --zip` / `--zip-append`, which store a LOCAL source as a STORE
member of a ZIP archive (member name == source basename). The server is never
touched for the local cases — all ZIP logic lives in libbrix (client/lib/copy.c,
client/lib/zip.c). Coverage:

  (1) local create:  --zip <file> <dst.zip>      -> unzip -t OK + member byte-exact
  (2) local append:  --zip-append <file2> <dst.zip> -> both members present+exact
  (3) remote create: --zip <file> root://.../<uuid>.zip -> download + unzip OK/exact
  (4) reader agree:  download root://.../<uuid>.zip?xrdcl.unzip=<member> -> exact

Uses the native clean-room xrdcp (client/xrdcp) against the harness anon server.
Skips cleanly if xrdcp / unzip is unavailable, or the root:// server is unreachable.
"""

import os
import shutil
import subprocess
import uuid

import pytest

from settings import NGINX_ANON_PORT

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://localhost:{NGINX_ANON_PORT}"

# Two distinct, non-trivial payloads (member name == source basename).
M1_NAME = "member_one.bin"
M1_DATA = bytes((i * 7 + 3) & 0xFF for i in range(40_000))
M2_NAME = "member_two.txt"
M2_DATA = b"second zip member payload \x00\x01\x02 line\n" * 4000


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _require_xrdcp():
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")


def _require_unzip():
    if shutil.which("unzip") is None:
        pytest.skip("unzip not available on PATH")


def _write_src(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _xrdcp(args, timeout=60):
    return _run([XRDCP] + args, timeout=timeout)


def _unzip_test(zpath):
    """`unzip -t` integrity check -> CompletedProcess."""
    return _run(["unzip", "-t", zpath])


def _unzip_member(zpath, member):
    """`unzip -p` to stdout (binary) -> (returncode, raw bytes, stderr)."""
    p = subprocess.run(["unzip", "-p", zpath, member],
                       capture_output=True, timeout=60)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def _unzip_list(zpath):
    """`unzip -l` listing text (member names) -> str."""
    return _run(["unzip", "-l", zpath]).stdout


# --------------------------------------------------------------------------- #
# (1) + (2) local create & append
# --------------------------------------------------------------------------- #
def test_zip_create_and_append_local(tmp_path):
    """--zip creates a 1-member archive; --zip-append adds a 2nd; both exact."""
    _require_xrdcp()
    _require_unzip()

    src1 = str(tmp_path / M1_NAME)
    src2 = str(tmp_path / M2_NAME)
    _write_src(src1, M1_DATA)
    _write_src(src2, M2_DATA)
    zpath = str(tmp_path / "out.zip")

    # (1) create
    r = _xrdcp(["--zip", src1, zpath])
    assert r.returncode == 0, f"--zip create failed: {r.stderr[:400]}"
    assert os.path.exists(zpath), "archive not created"

    t = _unzip_test(zpath)
    assert t.returncode == 0, f"unzip -t failed after create: {t.stdout}\n{t.stderr}"

    rc, got, err = _unzip_member(zpath, M1_NAME)
    assert rc == 0, f"unzip -p {M1_NAME} failed: {err}"
    assert got == M1_DATA, f"{M1_NAME}: not byte-exact after create"

    # (2) append a second member
    r = _xrdcp(["--zip-append", src2, zpath])
    assert r.returncode == 0, f"--zip-append failed: {r.stderr[:400]}"

    t = _unzip_test(zpath)
    assert t.returncode == 0, f"unzip -t failed after append: {t.stdout}\n{t.stderr}"

    listing = _unzip_list(zpath)
    assert M1_NAME in listing, f"first member missing after append:\n{listing}"
    assert M2_NAME in listing, f"second member missing after append:\n{listing}"

    # both members byte-exact
    rc, got1, err1 = _unzip_member(zpath, M1_NAME)
    assert rc == 0, f"unzip -p {M1_NAME} failed after append: {err1}"
    assert got1 == M1_DATA, f"{M1_NAME}: not byte-exact after append"

    rc, got2, err2 = _unzip_member(zpath, M2_NAME)
    assert rc == 0, f"unzip -p {M2_NAME} failed after append: {err2}"
    assert got2 == M2_DATA, f"{M2_NAME}: not byte-exact after append"


# --------------------------------------------------------------------------- #
# (3) + (4) remote create, download, unzip, and OUR-reader round-trip
# --------------------------------------------------------------------------- #
@pytest.fixture()
def remote_zip(tmp_path):
    """Build a 1-member ZIP directly on the root:// server with `--zip`.

    Yields (remote_path, src_data, member_name); best-effort xrdfs rm cleanup.
    """
    _require_xrdcp()

    src = str(tmp_path / M1_NAME)
    _write_src(src, M1_DATA)

    remote = f"/zipwrite_{uuid.uuid4().hex}.zip"
    up = _xrdcp(["--zip", src, f"{BASE}{remote}"])
    if up.returncode != 0:
        pytest.skip(f"could not create remote ZIP on root:// server: {up.stderr[:300]}")

    yield remote, M1_DATA, M1_NAME

    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def test_zip_remote_create_download_unzip(remote_zip, tmp_path):
    """--zip to root://, download the .zip, then unzip -t OK + member exact."""
    _require_unzip()
    remote, data, member = remote_zip

    local = str(tmp_path / "downloaded.zip")
    dl = _xrdcp(["-f", f"{BASE}{remote}", local])
    assert dl.returncode == 0, f"download of remote ZIP failed: {dl.stderr[:400]}"
    assert os.path.exists(local), "downloaded archive missing"

    t = _unzip_test(local)
    assert t.returncode == 0, f"unzip -t failed on downloaded archive: {t.stdout}\n{t.stderr}"

    rc, got, err = _unzip_member(local, member)
    assert rc == 0, f"unzip -p {member} failed: {err}"
    assert got == data, f"{member}: downloaded archive member not byte-exact"


def test_zip_remote_our_reader_roundtrip(remote_zip, tmp_path):
    """Writer<->reader agreement: extract the member via ?xrdcl.unzip= -> exact."""
    remote, data, member = remote_zip

    out = str(tmp_path / "member.out")
    url = f"{BASE}{remote}?xrdcl.unzip={member}"
    r = _xrdcp(["-f", url, out])
    assert r.returncode == 0, f"?xrdcl.unzip extract failed: {r.stderr[:400]}"
    assert os.path.exists(out), "no output from ?xrdcl.unzip reader"

    with open(out, "rb") as fh:
        got = fh.read()
    assert got == data, f"{member}: writer/reader disagree (not byte-exact)"
