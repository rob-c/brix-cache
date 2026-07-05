"""
Phase-42 W5 — root:// inline WRITE compression (client compresses each kXR_write
payload, server decompresses on ingest and stores plaintext).

The symmetric inverse of W4: `xrdcp --compress <codec>` on an UPLOAD makes the
native client compress each write frame; the server (brix_write_compress on,
which the harness anon server has) decompresses it under a bomb guard and stores
the file plaintext.  Wire bytes shrink; the bytes on disk (and read back) are
byte-identical to the source.

Drives the harness anonymous root:// server (port 11094) with the native xrdcp.
Asserts: every codec uploads byte-exact; compression actually engaged (the anon
access log WRITE line carries the "z=<wirebytes>" marker only on the compressed
path); a plain upload is byte-identical and shows NO marker (opt-in invisibility);
a large multi-frame upload round-trips (write frames are offset-addressable); an
unknown codec degrades to plaintext; and the server advertises cmpwrite.
"""

import os
import subprocess
import time
import uuid

import pytest

from settings import NGINX_ANON_PORT, LOG_DIR

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://localhost:{NGINX_ANON_PORT}"
ANON_ACCESS_LOG = os.path.join(LOG_DIR, "brix_access_anon.log")

CODECS = ["gzip", "deflate", "zstd", "br", "xz", "bzip2", "lz4"]

# Compressible but content-rich, so the server genuinely compresses yet every
# byte is determinate for a byte-exact comparison.
PAYLOAD = (b"the quick brown fox jumps over the lazy dog 0123456789 "
           b"lorem ipsum dolor sit amet ") * 24000     # ~1.9 MiB


@pytest.fixture(scope="module")
def src(tmp_path_factory):
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    d = tmp_path_factory.mktemp("cmpwrite")
    p = str(d / "payload.bin")
    with open(p, "wb") as fh:
        fh.write(PAYLOAD)
    # confirm the anon server is reachable + writable
    probe = f"/cmpw_probe_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", p, f"{BASE}{probe}"],
                        capture_output=True, text=True, timeout=60)
    if up.returncode != 0:
        pytest.skip(f"anon root:// server not writable: {up.stderr[:200]}")
    subprocess.run([XRDFS, BASE, "rm", probe], capture_output=True)
    yield p


def _rm(remote):
    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def _upload(src_path, remote, codec=None):
    cmd = [XRDCP, "-f"]
    if codec is not None:
        cmd += ["--compress", codec]
    cmd += [src_path, f"{BASE}{remote}"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def _download(remote, out):
    return subprocess.run([XRDCP, "-f", f"{BASE}{remote}", out],
                          capture_output=True, text=True, timeout=120)


def _log_has_compressed_write(remote):
    """The anon access log shows a compressed WRITE (z= marker) for `remote`."""
    base = os.path.basename(remote)
    for _ in range(30):
        try:
            with open(ANON_ACCESS_LOG, "r", errors="replace") as fh:
                for line in fh:
                    if "WRITE" in line and base in line and "z=" in line:
                        return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


@pytest.mark.parametrize("codec", CODECS)
def test_upload_compressed_byte_exact(src, tmp_path, codec):
    """Upload --compress <codec>; the server decompresses on ingest and the file
    read back is byte-identical to the source."""
    remote = f"/cmpw_{codec}_{uuid.uuid4().hex}.bin"
    out = str(tmp_path / f"{codec}.out")
    try:
        r = _upload(src, remote, codec=codec)
        assert r.returncode == 0, f"--compress {codec} upload failed: {r.stderr[:300]}"
        d = _download(remote, out)
        assert d.returncode == 0, f"download failed: {d.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == PAYLOAD, f"{codec}: upload not byte-exact"
    finally:
        _rm(remote)


def test_gzip_upload_actually_compresses(src):
    """gzip is always built in, so a --compress gzip upload MUST take the
    write-decompress path — proven by the 'z=' WRITE marker.  Catches a regression
    where the client silently sends plaintext or the server skips decompression."""
    remote = f"/cmpw_proof_{uuid.uuid4().hex}.bin"
    try:
        assert _upload(src, remote, codec="gzip").returncode == 0
        assert _log_has_compressed_write(remote), \
            "no compressed WRITE (z=) logged — write compression did not engage"
    finally:
        _rm(remote)


def test_plain_upload_byte_exact_and_invisible(src, tmp_path):
    """Opt-in proof: with write_compress ON but no --compress, the upload is the
    untouched plaintext path — byte-identical and with NO z= marker."""
    remote = f"/cmpw_plain_{uuid.uuid4().hex}.bin"
    out = str(tmp_path / "plain.out")
    try:
        assert _upload(src, remote).returncode == 0
        assert _download(remote, out).returncode == 0
        with open(out, "rb") as fh:
            assert fh.read() == PAYLOAD, "plain upload not byte-exact"
        assert not _log_has_compressed_write(remote), \
            "plain upload unexpectedly took the compressed path"
    finally:
        _rm(remote)


def test_large_multiframe_upload(src, tmp_path):
    """A large upload spans many kXR_write frames at increasing offsets; each is an
    independent compressed frame the server decompresses at its own offset.  Proves
    write frames are offset-addressable (a wrong offset would corrupt the file)."""
    big = str(tmp_path / "big.bin")
    payload = PAYLOAD * 11           # ~21 MiB → many write frames
    with open(big, "wb") as fh:
        fh.write(payload)
    remote = f"/cmpw_big_{uuid.uuid4().hex}.bin"
    out = str(tmp_path / "big.out")
    try:
        r = _upload(big, remote, codec="zstd")
        assert r.returncode == 0, f"large upload failed: {r.stderr[:300]}"
        assert _download(remote, out).returncode == 0
        with open(out, "rb") as fh:
            assert fh.read() == payload, "large multi-frame upload not byte-exact"
    finally:
        _rm(remote)


def test_bogus_codec_degrades_to_plaintext(src, tmp_path):
    """An unknown codec must not fail the upload: the server ignores the opaque,
    the client sends plaintext, and the file is byte-exact."""
    remote = f"/cmpw_bogus_{uuid.uuid4().hex}.bin"
    out = str(tmp_path / "bogus.out")
    try:
        r = _upload(src, remote, codec="notacodec")
        assert r.returncode == 0, f"bogus-codec upload failed: {r.stderr[:300]}"
        assert _download(remote, out).returncode == 0
        with open(out, "rb") as fh:
            assert fh.read() == PAYLOAD, "bogus codec: upload not byte-exact"
    finally:
        _rm(remote)


def test_cmpwrite_advertised():
    """The server advertises the write-compression codecs via kXR_Qconfig cmpwrite
    when brix_write_compress is on."""
    if not os.access(XRDFS, os.X_OK):
        pytest.skip("xrdfs not built")
    r = subprocess.run([XRDFS, BASE, "query", "config", "cmpwrite"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        pytest.skip(f"xrdfs query config cmpwrite unsupported: {r.stderr[:200]}")
    out = r.stdout.strip()
    assert "cmpwrite=" in out and "gzip" in out, \
        f"cmpwrite advertisement missing/empty: {out!r}"
