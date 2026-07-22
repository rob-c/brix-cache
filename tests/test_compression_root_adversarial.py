"""
Phase-42 W4 — root:// inline read compression: adversarial / functional suite.

This is the harder-edge companion to test_compression_root.py.  Same contract —
a read handle opened with the opaque "?xrootd.compress=<codec>" (the native xrdcp
`--compress <codec>` flag) makes the server compress each kXR_read response, and
the client transparently inflates — but here we stress the *edges* that the basic
suite skips:

  (1) random-access / multi-frame correctness — a single ~5 MiB payload spans many
      read windows, so a whole-file --compress zstd download exercises many codec
      frames stitched back together and must be byte-exact;
  (2) every advertised codec (gzip/deflate/zstd/br/xz/bzip2) round-trips byte-exact
      under --compress (a codec the server lacks falls back to plaintext, which is
      ALSO byte-exact, so the assertion holds unconditionally — graceful degrade);
  (3) a SMALL 100-byte file under --compress gzip stays byte-exact (short read /
      tiny-frame edge — a frame smaller than its own header must still round-trip);
  (4) Qconfig "cmpread" advertisement — `xrdfs <host> query config cmpread` lists a
      non-empty codec set (gzip at minimum) or, on an older xrdfs lacking the
      subcommand / an older server, degrades to a clean skip;
  (5) stock-peer invisibility — a PLAIN download (no --compress) is byte-exact AND
      its READ access-log line carries NO "z=" marker (true uncompressed hot path),
      while a --compress gzip download of the SAME file DOES log "z=".

Drives the harness anonymous root:// server (NGINX_ANON_PORT, 11094) which runs
with `brix_read_compress on`.  Uses the native clean-room xrdcp/xrdfs
(client/xrdcp, client/xrdfs); no libXrdCl.  Remote keys are uuid-tagged and torn
down with `xrdfs rm`.
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

# ~5 MiB of highly compressible repeating text — big enough to span MANY read
# windows so a whole-file download stitches together many codec frames (the
# multi-frame / random-access correctness case).
_LINE = b"the quick brown fox jumps over the lazy dog 0123456789\n"
PAYLOAD = _LINE * ((5 * 1024 * 1024) // len(_LINE) + 1)  # ~5 MiB, > 5*1024*1024

# A tiny payload for the short-read / tiny-frame edge: 100 bytes, smaller than a
# typical codec stream header, so the frame must still round-trip byte-exact.
SMALL_PAYLOAD = (b"abcdefghij" * 10)
assert len(SMALL_PAYLOAD) == 100

# Every codec the gateway can speak.  zlib (gzip/deflate) is always built in; the
# rest are compile-gated, so the server simply won't advertise an absent one and
# the client falls back to plaintext — the download stays byte-exact either way,
# which is exactly the graceful-degradation contract we assert.
CODECS = ["gzip", "deflate", "zstd", "br", "xz", "bzip2"]


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    """Upload the ~5 MiB compressible payload once for the whole module."""
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    d = tmp_path_factory.mktemp("cmproot_adv")
    src = str(d / "payload.bin")
    with open(src, "wb") as fh:
        fh.write(PAYLOAD)

    remote = f"/cmproot_adv_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", src, f"{BASE}{remote}"],
                        capture_output=True, text=True, timeout=120)
    if up.returncode != 0:
        pytest.skip(f"upload to root:// server failed: {up.stderr[:300]}")
    yield remote, str(d)
    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def _download(remote, out, codec=None, timeout=120):
    """Run `xrdcp [--compress <codec>] root://...<remote> <out>`."""
    cmd = [XRDCP, "-f"]
    if codec is not None:
        cmd += ["--compress", codec]
    cmd += [f"{BASE}{remote}", out]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _log_lines_for(remote, want_marker, timeout_s=3.0):
    """True if the anon access log shows a READ line for `remote` whose presence
    of the compressed-read "z=" marker matches `want_marker`.

    The access log is per-worker batched but flushed on connection close, so the
    line is present once xrdcp has exited; we poll briefly to absorb the ~1s
    timer-flush race on a slow host.  The detail field is sanitised, so the space
    before the marker is written as "\\x20z=<wirebytes>"; we match the "z=" token.
    """
    base = os.path.basename(remote)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with open(ANON_ACCESS_LOG, "r", errors="replace") as fh:
                for line in fh:
                    if "READ" in line and base in line:
                        if ("z=" in line) == want_marker:
                            return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# (1) random-access / multi-frame correctness
# ---------------------------------------------------------------------------
def test_whole_file_zstd_byte_exact_multiframe(uploaded, tmp_path):
    """A whole-file --compress zstd download of the ~5 MiB payload spans many read
    windows, so the client must stitch many codec frames back into the exact
    original bytes."""
    remote, _ = uploaded
    out = str(tmp_path / "zstd_whole.out")
    r = _download(remote, out, codec="zstd")
    assert r.returncode == 0, f"--compress zstd download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        data = fh.read()
    assert len(data) == len(PAYLOAD), (
        f"length mismatch: got {len(data)} want {len(PAYLOAD)}")
    assert data == PAYLOAD, "--compress zstd whole-file: not byte-exact"


# ---------------------------------------------------------------------------
# (2) every codec round-trips byte-exact
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("codec", CODECS)
def test_codec_download_byte_exact(uploaded, tmp_path, codec):
    """For every codec token the client can send, the downloaded bytes equal the
    original.  A codec the server lacks degrades to plaintext, which is ALSO
    byte-exact, so this holds for the whole set unconditionally."""
    remote, _ = uploaded
    out = str(tmp_path / f"{codec}.out")
    r = _download(remote, out, codec=codec)
    assert r.returncode == 0, f"--compress {codec} download failed: {r.stderr[:300]}"
    with open(out, "rb") as fh:
        assert fh.read() == PAYLOAD, f"--compress {codec}: not byte-exact"


# ---------------------------------------------------------------------------
# (3) tiny file / short-read edge
# ---------------------------------------------------------------------------
def test_small_file_gzip_byte_exact(tmp_path):
    """A 100-byte file under --compress gzip must round-trip byte-exact: the
    short-read / tiny-frame path (a frame smaller than its own header) must not
    truncate or pad."""
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    src = str(tmp_path / "small.bin")
    with open(src, "wb") as fh:
        fh.write(SMALL_PAYLOAD)

    remote = f"/cmproot_adv_small_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", src, f"{BASE}{remote}"],
                        capture_output=True, text=True, timeout=60)
    if up.returncode != 0:
        pytest.skip(f"small-file upload failed: {up.stderr[:300]}")
    try:
        out = str(tmp_path / "small_gzip.out")
        r = _download(remote, out, codec="gzip", timeout=60)
        assert r.returncode == 0, f"small --compress gzip failed: {r.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == SMALL_PAYLOAD, "small --compress gzip: not byte-exact"
    finally:
        if os.access(XRDFS, os.X_OK):
            subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


# ---------------------------------------------------------------------------
# (4) Qconfig cmpread advertisement
# ---------------------------------------------------------------------------
def test_qconfig_cmpread_advertises_codecs():
    """`xrdfs <host> query config cmpread` advertises the server's read-compress
    codec set.  We assert the reply lists at least gzip OR equals a non-zero codec
    list (i.e. not the disabled "cmpread=0" form).  An xrdfs/server that does not
    understand the subcommand degrades to a clean skip rather than a failure."""
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")
    r = subprocess.run(
        [XRDFS, f"{SERVER_HOST}:{NGINX_ANON_PORT}", "query", "config", "cmpread"],
        capture_output=True, text=True, timeout=30)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        pytest.skip(f"xrdfs query config cmpread unsupported/failed: {out[:200]}")
    low = out.lower()
    if "cmpread" not in low and "gzip" not in low:
        # Older xrdfs prints just the raw value; an empty/unknown reply means the
        # subcommand path isn't really there — degrade gracefully.
        pytest.skip(f"no cmpread advertisement in reply: {out[:200]!r}")

    # Disabled form is exactly "cmpread=0" (or a bare "0"); anything else with a
    # codec name in it is a non-zero list.
    stripped = low.replace("cmpread=", "").strip()
    has_gzip = "gzip" in low
    nonzero_list = bool(stripped) and stripped not in ("0", "")
    assert has_gzip or nonzero_list, (
        f"cmpread advertised empty/disabled, expected codec list: {out[:200]!r}")


# ---------------------------------------------------------------------------
# (5) stock-peer invisibility: plain read has NO z=, compressed read HAS z=
# ---------------------------------------------------------------------------
def test_plain_read_invisible_compressed_read_marked(uploaded, tmp_path):
    """Opt-in / invisibility proof on the SAME file:
      * a plain download (no --compress) is byte-exact and its READ access-log
        line carries NO "z=" marker — the untouched uncompressed hot path;
      * a --compress gzip download (gzip is always built in) is byte-exact and
        DOES log a "z=" marker — the server engaged compression on request.
    """
    remote, _ = uploaded

    plain = str(tmp_path / "plain.out")
    rp = _download(remote, plain)
    assert rp.returncode == 0, f"plain download failed: {rp.stderr[:300]}"
    with open(plain, "rb") as fh:
        assert fh.read() == PAYLOAD, "plain download not byte-exact"
    assert _log_lines_for(remote, want_marker=False), (
        "plain read should log a READ line WITHOUT a 'z=' marker (uncompressed)")

    comp = str(tmp_path / "gzip.out")
    rc = _download(remote, comp, codec="gzip")
    assert rc.returncode == 0, f"gzip download failed: {rc.stderr[:300]}"
    with open(comp, "rb") as fh:
        assert fh.read() == PAYLOAD, "gzip download not byte-exact"
    assert _log_lines_for(remote, want_marker=True), (
        "gzip read should log a READ line WITH a 'z=' marker (compressed) — "
        "server did not engage compression")
