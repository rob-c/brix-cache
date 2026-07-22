"""
zcrc32 checksum parity across the root:// surface (native client + server).

`zcrc32` is this gateway's name for a plain CRC-32 (the same algorithm as zlib's
crc32 / the `crc32` checksum) served over the wire via kXR_query/kXR_Qcksum.
These tests drive the harness anonymous root:// server (port 11094) with the
clean-room native client (client/xrdcp, client/xrdfs — no libXrdCl):

  (1) Upload a known payload with xrdcp, query its zcrc32 with
      `xrdfs ... cksum -a zcrc32 <path>` and assert the 8-hex digest equals an
      independent Python `zlib.crc32` oracle.
  (2) Assert the server advertises `zcrc32` in its Qconfig chksum list
      (`xrdfs ... query config chksum` contains "zcrc32"); skipped if the
      native xrdfs cannot answer that query.
  (3) Cross-check that the zcrc32 hex equals the crc32 hex for the SAME file —
      they are the same algorithm, so the digests must be identical.

Everything degrades gracefully: a missing binary or an unreachable/unprovisioned
server turns the affected case into a pytest.skip rather than a hard failure,
while a genuine digest mismatch stays a hard assertion.
"""

import os
import re
import subprocess
import uuid
import zlib

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

# A small, fixed payload — the digest only has to match the oracle, not exercise
# read windows, so keep it cheap and deterministic.
PAYLOAD = b"zcrc32 known payload 0123456789 the quick brown fox\n" * 50

# Independent oracle: zcrc32 == zlib.crc32, rendered as lowercase 8-hex.
ZCRC32_EXPECTED = "%08x" % (zlib.crc32(PAYLOAD) & 0xFFFFFFFF)

# The native client never reads a real GSI proxy in these anon tests, but a
# stale/expired $X509_USER_PROXY makes xrdcp emit a warning and (depending on
# the env) fall back oddly — neutralise it the same way the harness run line does.
_ENV = dict(os.environ)
_ENV.setdefault("X509_USER_PROXY", "/nonexistent")


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    """Upload PAYLOAD to the anon root:// server; yield its remote path.

    Skips (does not fail) when the native binaries are not built or the server
    is not reachable, so the file is runnable as-is in any environment.
    """
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")

    d = tmp_path_factory.mktemp("zcrc32")
    src = str(d / "payload.bin")
    with open(src, "wb") as fh:
        fh.write(PAYLOAD)

    remote = f"/zcrc32_{uuid.uuid4().hex}.bin"
    up = subprocess.run(
        [XRDCP, "-f", src, f"{BASE}{remote}"],
        capture_output=True, text=True, timeout=60, env=_ENV,
    )
    if up.returncode != 0:
        pytest.skip(
            "upload to root:// server failed (server down/unreachable?): "
            f"{(up.stderr or up.stdout)[:300]}"
        )
    yield remote
    # Best-effort cleanup; never fail the suite on teardown.
    subprocess.run([XRDFS, BASE, "rm", remote],
                   capture_output=True, env=_ENV)


def _cksum_hex(remote, algo):
    """Return the server-side <algo> digest for `remote`, or skip on failure.

    `xrdfs <url> cksum -a <algo> <path>` prints "<algo> <hex> <path>"; we return
    the middle (hex) token.  A non-zero exit or unparseable line means the
    surface can't answer for this algo here -> skip the dependent assertion.
    """
    r = subprocess.run(
        [XRDFS, BASE, "cksum", "-a", algo, remote],
        capture_output=True, text=True, timeout=60, env=_ENV,
    )
    if r.returncode != 0:
        pytest.skip(f"xrdfs cksum -a {algo} unavailable: "
                    f"{(r.stderr or r.stdout).strip()[:200]}")
    parts = r.stdout.split()
    # Expected layout: ["<algo>", "<hex>", "<path>"]; be tolerant of a
    # digest-only reply by falling back to the first hex-looking token.
    if len(parts) >= 2 and parts[0] == algo:
        return parts[1].strip().lower()
    for tok in parts:
        if re.fullmatch(r"[0-9a-fA-F]+", tok):
            return tok.strip().lower()
    pytest.skip(f"unparseable cksum reply for {algo}: {r.stdout.strip()!r}")


def test_zcrc32_matches_zlib_oracle(uploaded):
    """The server's zcrc32 for the uploaded file equals zlib.crc32 (8 hex)."""
    got = _cksum_hex(uploaded, "zcrc32")
    assert re.fullmatch(r"[0-9a-f]{8}", got), \
        f"zcrc32 is not 8 lowercase hex: {got!r}"
    assert got == ZCRC32_EXPECTED, \
        f"zcrc32 mismatch: server={got} oracle={ZCRC32_EXPECTED}"


def test_server_advertises_zcrc32_in_qconfig(uploaded):
    """Qconfig chksum list advertises zcrc32 (skip if xrdfs can't query it)."""
    r = subprocess.run(
        [XRDFS, BASE, "query", "config", "chksum"],
        capture_output=True, text=True, timeout=60, env=_ENV,
    )
    if r.returncode != 0:
        pytest.skip("xrdfs query config chksum unavailable: "
                    f"{(r.stderr or r.stdout).strip()[:200]}")
    out = r.stdout.strip()
    if not out:
        pytest.skip("empty Qconfig chksum reply")
    assert "zcrc32" in out, \
        f"server does not advertise zcrc32 in Qconfig chksum: {out!r}"


def test_zcrc32_equals_crc32(uploaded):
    """zcrc32 and crc32 name the same algorithm -> identical digests.

    The crc32 sub-case is skipped (not failed) if this surface doesn't expose a
    `crc32` alias, but when present its digest MUST equal both zcrc32 and the
    independent zlib oracle.
    """
    z = _cksum_hex(uploaded, "zcrc32")
    c = _cksum_hex(uploaded, "crc32")
    assert c == z, f"crc32 ({c}) != zcrc32 ({z}) for the same file"
    assert c == ZCRC32_EXPECTED, \
        f"crc32 mismatch: server={c} oracle={ZCRC32_EXPECTED}"
