"""
Phase-42 W4 — root:// inline read compression (server + native client).

A read handle opened with the opaque "?xrootd.compress=<codec>" (the native
xrdcp `--compress <codec>` flag) makes the server compress each kXR_read response
with that codec; the client transparently inflates.  Everything is opt-in and
off by default: a plain download against the SAME server is byte-identical (the
uncompressed hot path is untouched), and an unknown/disabled codec degrades to
plaintext rather than failing.

These tests drive the harness anonymous root:// server (port 11094), which has
`brix_read_compress on`.  They:
  * upload a highly compressible payload with xrdcp,
  * download it WITHOUT --compress  -> byte-exact (regression / opt-in proof),
  * download it WITH --compress <c>  -> byte-exact for every codec,
  * confirm the server actually compressed (the anon access log READ line carries
    a "z=<wirebytes>" marker only on the compressed path),
  * confirm a bogus codec degrades gracefully to a byte-exact plaintext read.

Uses the native clean-room xrdcp (client/xrdcp); no libXrdCl.
"""

import os
import subprocess
import time
import uuid

import pytest

from settings import LOG_DIR, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
ANON_ACCESS_LOG = os.path.join(LOG_DIR, "brix_access_anon.log")

# Highly compressible: ~1.5 MiB of repeating text spans several read windows.
PAYLOAD = (b"the quick brown fox jumps over the lazy dog 0123456789\n" * 30000)

# Every codec the gateway can speak.  zlib (gzip/deflate) is always built in;
# the rest are compile-gated, so the server simply won't advertise an absent one
# and the client falls back to plaintext — the download stays byte-exact either
# way, which is exactly the graceful-degradation contract we want to assert.
CODECS = ["gzip", "deflate", "zstd", "br", "xz", "bzip2", "lz4"]


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    d = tmp_path_factory.mktemp("cmproot")
    src = str(d / "payload.bin")
    with open(src, "wb") as fh:
        fh.write(PAYLOAD)

    remote = f"/cmproot_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", src, f"{BASE}{remote}"],
                        capture_output=True, text=True, timeout=60)
    if up.returncode != 0:
        pytest.skip(f"upload to root:// server failed: {up.stderr[:300]}")
    yield remote, str(d)
    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def _download(remote, out, codec=None):
    cmd = [XRDCP, "-f"]
    if codec is not None:
        cmd += ["--compress", codec]
    cmd += [f"{BASE}{remote}", out]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def _log_has_compressed_read(remote):
    """True if the anon access log shows a compressed READ (z=) for `remote`.

    The access log is per-worker batched but flushed on connection close, so the
    line is present once xrdcp has exited; retry briefly to absorb the 1s timer
    flush race on a slow host.
    """
    # The access-log detail field is sanitised, so the space before the marker is
    # written as "\x20z=<wirebytes>"; match the "z=" marker itself.
    base = os.path.basename(remote)
    for _ in range(30):
        try:
            with open(ANON_ACCESS_LOG, "r", errors="replace") as fh:
                for line in fh:
                    if "READ" in line and base in line and "z=" in line:
                        return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


def test_plain_download_byte_exact(uploaded, tmp_path):
    """Opt-in proof: with read_compress ON but no --compress, the read is the
    untouched plaintext path and is byte-identical."""
    remote, _ = uploaded
    out = str(tmp_path / "plain.out")
    r = _download(remote, out)
    assert r.returncode == 0, f"plain download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == PAYLOAD, "plain download not byte-exact"


@pytest.mark.parametrize("codec", CODECS)
def test_compressed_download_byte_exact(uploaded, tmp_path, codec):
    remote, _ = uploaded
    out = str(tmp_path / f"{codec}.out")
    r = _download(remote, out, codec=codec)
    assert r.returncode == 0, f"--compress {codec} download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == PAYLOAD, f"--compress {codec}: not byte-exact"


def test_gzip_actually_compresses(uploaded, tmp_path):
    """gzip is always available (zlib is mandatory), so a --compress gzip read
    MUST take the compressed path — proven by the 'z=' marker in the access log.
    Catches a regression where the server silently serves plaintext."""
    remote, _ = uploaded
    out = str(tmp_path / "gzip_proof.out")
    r = _download(remote, out, codec="gzip")
    assert r.returncode == 0, f"gzip download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == PAYLOAD
    assert _log_has_compressed_read(remote), (
        "no compressed READ (z=) logged — server did not engage compression")


def test_bogus_codec_degrades_to_plaintext(uploaded, tmp_path):
    """An unknown codec must not fail the open: the server ignores the opaque,
    the client gets plaintext, and the download is still byte-exact."""
    remote, _ = uploaded
    out = str(tmp_path / "bogus.out")
    r = _download(remote, out, codec="notacodec")
    assert r.returncode == 0, f"bogus-codec download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == PAYLOAD, "bogus codec: not byte-exact"
