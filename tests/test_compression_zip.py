"""
Phase-42 W3 — ZIP archive member reads over root:// (client-side, zlib-only).

Builds a real ZIP (STORE + DEFLATE + a force-ZIP64 member), uploads it to the
anonymous root:// server with xrdcp, then extracts each member with
`xrdcp "root://host//archive.zip?xrdcl.unzip=<member>" out` and asserts the
output is byte-exact. The server is untouched — all ZIP logic is in libbrix
(client/lib/zip.c). Also checks a missing member fails cleanly.

Uses the native clean-room xrdcp (client/xrdcp) against the harness anon server.
"""

import os
import subprocess
import uuid
import zipfile

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

MEMBERS = {
    "stored.txt":   (bytes((i * 7) & 0xFF for i in range(5000)), zipfile.ZIP_STORED),
    "deflated.txt": (b"hello deflate world " * 3000, zipfile.ZIP_DEFLATED),
}
Z64_NAME = "z64.bin"
Z64_DATA = bytes((i * 13 + 1) & 0xFF for i in range(300_000))


@pytest.fixture(scope="module")
def archive(tmp_path_factory):
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    d = tmp_path_factory.mktemp("zip")
    zpath = str(d / "archive.zip")
    z = zipfile.ZipFile(zpath, "w")
    for name, (data, ctype) in MEMBERS.items():
        z.writestr(name, data, ctype)
    with z.open(Z64_NAME, "w", force_zip64=True) as f:
        f.write(Z64_DATA)
    z.close()

    remote = f"/cmpzip_{uuid.uuid4().hex}.zip"
    up = subprocess.run([XRDCP, "-f", zpath, f"{BASE}/{remote}"],
                        capture_output=True, text=True, timeout=60)
    if up.returncode != 0:
        pytest.skip(f"could not upload archive to root:// server: {up.stderr[:300]}")
    yield remote, str(d)
    # best-effort cleanup via xrdfs if present
    xrdfs = os.path.join(REPO, "client", "bin", "xrdfs")
    if os.access(xrdfs, os.X_OK):
        subprocess.run([xrdfs, BASE, "rm", remote], capture_output=True)


def _extract(remote, member, out):
    url = f"{BASE}/{remote}?xrdcl.unzip={member}"
    return subprocess.run([XRDCP, "-f", url, out],
                          capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("member", list(MEMBERS))
def test_zip_member_roundtrip(archive, tmp_path, member):
    remote, _ = archive
    out = str(tmp_path / f"{member}.out")
    r = _extract(remote, member, out)
    assert r.returncode == 0, f"{member} extract failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        got = fh.read()
    assert got == MEMBERS[member][0], f"{member}: not byte-exact"


def test_zip64_member_roundtrip(archive, tmp_path):
    remote, _ = archive
    out = str(tmp_path / "z64.out")
    r = _extract(remote, Z64_NAME, out)
    assert r.returncode == 0, f"zip64 extract failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == Z64_DATA, "zip64 member not byte-exact"


def test_zip_missing_member_fails(archive, tmp_path):
    remote, _ = archive
    out = str(tmp_path / "missing.out")
    r = _extract(remote, "no/such/member.bin", out)
    assert r.returncode != 0, "missing member should fail"
    assert not os.path.exists(out), "no output file should be left for a missing member"
