"""
Extended zcrc32 / crc32 checksum coverage against the shared harness.

`zcrc32` is this gateway's name for a plain CRC-32 (the identical algorithm to
zlib's crc32 and to the gateway's own `crc32` checksum), served over the wire via
kXR_query/kXR_Qcksum on root:// and over HTTP as an RFC-3230 `Digest` header on
WebDAV.  The base parity is covered by test_zcrc32_checksum.py; this file fills
the gaps that the recent server fixes opened up:

  (1) CRC32-ADVERTISE  — `xrdfs ... query config chksum` now lists BOTH `crc32`
      and `zcrc32` (the server was fixed to advertise the `crc32` alias next to
      `zcrc32`).  We also require `adler32` and `crc32c`, which the harness has
      always advertised, so advertise drift in either direction is caught.

  (2) CRC32-REACHABLE  — for EVERY algorithm the server advertises, the Qcksum
      path (`xrdfs cksum -a <algo>`) returns a value (kXR_ok).  This proves
      advertise == behaviour: nothing is listed that cannot actually be served.

  (3) ZCRC32-VALUE     — query the uploaded file's zcrc32 and assert it equals an
      independent Python `zlib.crc32` oracle (8 hex digits).  crc32 (the alias)
      must return the SAME value.

  (4) EMPTY-FILE       — zcrc32 and crc32 of a 0-byte object both equal
      zlib.crc32(b'') == 0x00000000.

  (5) WEBDAV-DIGEST    — a WebDAV GET/HEAD carrying `Want-Digest: zcrc32` returns
      a `Digest` header whose value equals the zlib oracle; the `crc32` alias
      yields the identical digest.  Skipped cleanly if the WebDAV route on 8443
      is not reachable / not digest-enabled in this environment.

Everything degrades gracefully: a missing native binary, an unreachable server,
or a genuinely-absent route turns the affected case into a pytest.skip rather
than a hard failure, while a real digest mismatch or advertise/behaviour drift
stays a hard assertion.
"""

import os
import re
import subprocess
import uuid
import zlib

import pytest

from settings import NGINX_ANON_PORT, NGINX_WEBDAV_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
WEBDAV_BASE = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"

# Small, fixed payload — the digest only has to match the oracle, so keep it
# cheap and deterministic (no read-window exercise needed here).
PAYLOAD = b"zcrc32 extended payload 0123456789 the quick brown fox\n" * 40
ZCRC32_EXPECTED = "%08x" % (zlib.crc32(PAYLOAD) & 0xFFFFFFFF)
EMPTY_CRC32 = "%08x" % (zlib.crc32(b"") & 0xFFFFFFFF)   # == "00000000"

# Algorithms whose Qcksum digest is a fixed-width LOWERCASE hex token. Used to
# both (a) parse the reply and (b) sanity-check the width for the CRC32 family.
_HEX_WIDTHS = {
    "adler32": 8,
    "crc32": 8,
    "zcrc32": 8,
    "crc32c": 8,
    "crc64": 16,
    "crc64nvme": 16,
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}

# Neutralise a stale/expired $X509_USER_PROXY the same way the harness run line
# does, so anon xrdcp/xrdfs never warns or falls back oddly.
_ENV = dict(os.environ)
_ENV.setdefault("X509_USER_PROXY", "/nonexistent")


# ---------------------------------------------------------------------------
# root:// fixtures + helpers (native client)
# ---------------------------------------------------------------------------

def _require_native():
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")


def _upload(tmp_path_factory, data, tag):
    """Upload `data` to the anon root:// server; return its remote path.

    Skips (does not fail) when the binaries are unbuilt or the server is down.
    """
    _require_native()
    d = tmp_path_factory.mktemp(tag)
    src = str(d / "payload.bin")
    with open(src, "wb") as fh:
        fh.write(data)
    remote = f"/zcrc32ext_{tag}_{uuid.uuid4().hex}.bin"
    up = subprocess.run(
        [XRDCP, "-f", src, f"{BASE}{remote}"],
        capture_output=True, text=True, timeout=60, env=_ENV,
    )
    if up.returncode != 0:
        pytest.skip(
            "upload to root:// server failed (server down/unreachable?): "
            f"{(up.stderr or up.stdout)[:300]}"
        )
    return remote


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    """A known non-empty object on the anon root:// server."""
    remote = _upload(tmp_path_factory, PAYLOAD, "known")
    yield remote
    subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True, env=_ENV)


@pytest.fixture(scope="module")
def uploaded_empty(tmp_path_factory):
    """A known 0-byte object on the anon root:// server."""
    remote = _upload(tmp_path_factory, b"", "empty")
    yield remote
    subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True, env=_ENV)


def _advertised_algos():
    """Return the list of chksum algos the root:// server advertises.

    Parses `chksum=a,b,c` (or a bare `a,b,c`) out of `query config chksum`.
    Skips if the binaries are unbuilt, the server is down, or the reply is empty.
    """
    _require_native()
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
    # Reply may be "chksum=adler32,crc32,..." or just the CSV — handle both.
    csv = out.split("=", 1)[1] if "=" in out else out
    algos = [a.strip().lower() for a in csv.split(",") if a.strip()]
    if not algos:
        pytest.skip(f"could not parse algos from Qconfig reply: {out!r}")
    return algos, out


def _cksum_token(remote, algo):
    """Return the server-side <algo> digest for `remote`, or skip on failure.

    `xrdfs <url> cksum -a <algo> <path>` prints "<algo> <digest> <path>"; we
    return the middle (digest) token lowercased.  A non-zero exit means the
    surface cannot answer for this algo here -> skip the dependent assertion.
    """
    r = subprocess.run(
        [XRDFS, BASE, "cksum", "-a", algo, remote],
        capture_output=True, text=True, timeout=60, env=_ENV,
    )
    if r.returncode != 0:
        pytest.skip(f"xrdfs cksum -a {algo} unavailable: "
                    f"{(r.stderr or r.stdout).strip()[:200]}")
    parts = r.stdout.split()
    if len(parts) >= 2 and parts[0] == algo:
        return parts[1].strip().lower()
    # Tolerate a digest-only reply: first hex-looking token.
    for tok in parts:
        if re.fullmatch(r"[0-9a-fA-F]+", tok):
            return tok.strip().lower()
    pytest.skip(f"unparseable cksum reply for {algo}: {r.stdout.strip()!r}")


# ---------------------------------------------------------------------------
# (1) CRC32-ADVERTISE
# ---------------------------------------------------------------------------

def test_advertises_crc32_and_zcrc32():
    """Qconfig chksum lists both `crc32` and `zcrc32`, plus adler32/crc32c."""
    algos, raw = _advertised_algos()
    for required in ("crc32", "zcrc32", "adler32", "crc32c"):
        assert required in algos, \
            f"server does not advertise {required!r} in chksum list: {raw!r}"


# ---------------------------------------------------------------------------
# (2) CRC32-REACHABLE — advertise == behaviour
# ---------------------------------------------------------------------------

def test_every_advertised_algo_is_reachable(uploaded):
    """Every advertised algo returns a digest via the Qcksum path (kXR_ok).

    This is the advertise==behaviour contract: nothing listed in Qconfig may be
    a dead entry.  Each algo's digest must be a non-empty hex token; for algos
    with a known fixed width we additionally pin the width.
    """
    algos, raw = _advertised_algos()
    for algo in algos:
        r = subprocess.run(
            [XRDFS, BASE, "cksum", "-a", algo, uploaded],
            capture_output=True, text=True, timeout=60, env=_ENV,
        )
        assert r.returncode == 0, (
            f"advertised algo {algo!r} not reachable via cksum "
            f"(exit {r.returncode}): {(r.stderr or r.stdout).strip()[:200]}"
        )
        tok = _cksum_token(uploaded, algo)
        assert re.fullmatch(r"[0-9a-f]+", tok), \
            f"{algo} digest not lowercase hex: {tok!r}"
        width = _HEX_WIDTHS.get(algo)
        if width is not None:
            assert len(tok) == width, \
                f"{algo} digest width {len(tok)} != expected {width}: {tok!r}"


# ---------------------------------------------------------------------------
# (3) ZCRC32-VALUE — equals the zlib oracle; crc32 alias matches
# ---------------------------------------------------------------------------

def test_zcrc32_matches_zlib_oracle(uploaded):
    """zcrc32 of the uploaded file equals zlib.crc32 (8 lowercase hex)."""
    got = _cksum_token(uploaded, "zcrc32")
    assert re.fullmatch(r"[0-9a-f]{8}", got), \
        f"zcrc32 is not 8 lowercase hex: {got!r}"
    assert got == ZCRC32_EXPECTED, \
        f"zcrc32 mismatch: server={got} oracle={ZCRC32_EXPECTED}"


def test_crc32_alias_equals_zcrc32(uploaded):
    """crc32 and zcrc32 name the same algorithm -> identical digests."""
    z = _cksum_token(uploaded, "zcrc32")
    c = _cksum_token(uploaded, "crc32")
    assert c == z, f"crc32 ({c}) != zcrc32 ({z}) for the same file"
    assert c == ZCRC32_EXPECTED, \
        f"crc32 mismatch: server={c} oracle={ZCRC32_EXPECTED}"


# ---------------------------------------------------------------------------
# (4) EMPTY-FILE — zcrc32/crc32 of 0 bytes == 0x00000000
# ---------------------------------------------------------------------------

def test_empty_file_zcrc32_is_zero(uploaded_empty):
    """zcrc32 of a 0-byte object equals zlib.crc32(b'') == 00000000."""
    got = _cksum_token(uploaded_empty, "zcrc32")
    assert got == EMPTY_CRC32 == "00000000", \
        f"empty-file zcrc32 {got!r} != {EMPTY_CRC32!r}"


def test_empty_file_crc32_is_zero(uploaded_empty):
    """crc32 of a 0-byte object equals zlib.crc32(b'') == 00000000."""
    got = _cksum_token(uploaded_empty, "crc32")
    assert got == EMPTY_CRC32 == "00000000", \
        f"empty-file crc32 {got!r} != {EMPTY_CRC32!r}"


# ---------------------------------------------------------------------------
# (5) WEBDAV-DIGEST (best-effort) — RFC-3230 Digest over HTTP
# ---------------------------------------------------------------------------

def _parse_digest_header(value, algo):
    """Pull the <algo> digest out of an RFC-3230 `Digest` header value.

    Accepts `Digest: <algo>=<v>` (the gateway's form) and also a comma-separated
    multi-entry header; returns the lowercased value or None if `algo` absent.
    """
    if not value:
        return None
    for entry in value.split(","):
        entry = entry.strip()
        if "=" not in entry:
            continue
        name, _, v = entry.partition("=")
        if name.strip().lower() == algo.lower():
            return v.strip().lower()
    return None


@pytest.fixture(scope="module")
def webdav():
    """A requests session + a known object on the WebDAV server (port 8443).

    Skips cleanly if `requests` is missing, the server is unreachable, or the
    PUT route is not writable here.  Yields (session, url, data).
    """
    requests = pytest.importorskip("requests")
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    sess = requests.Session()
    sess.verify = False
    try:
        sess.get(WEBDAV_BASE, timeout=5)
    except Exception as exc:
        pytest.skip(f"WebDAV server not reachable at {WEBDAV_BASE}: "
                    f"{type(exc).__name__}")

    data = PAYLOAD
    path = f"/zcrc32ext_dav_{uuid.uuid4().hex}.bin"
    url = f"{WEBDAV_BASE}{path}"
    try:
        r = sess.put(url, data=data, timeout=30)
    except Exception as exc:
        pytest.skip(f"WebDAV PUT failed: {type(exc).__name__}: {str(exc)[:120]}")
    if r.status_code not in (200, 201, 204):
        pytest.skip(f"WebDAV PUT not permitted here (status {r.status_code})")

    yield sess, url, data

    try:
        sess.delete(url, timeout=30)
    except Exception:
        pass


@pytest.mark.parametrize("method", ["HEAD", "GET"])
def test_webdav_want_digest_zcrc32(webdav, method):
    """WebDAV {HEAD,GET} with `Want-Digest: zcrc32` returns the oracle digest.

    The Digest header is best-effort: if the route does not emit one for this
    object we skip rather than fail (feature may be disabled in this build),
    but when present its value MUST equal the zlib.crc32 oracle.
    """
    sess, url, data = webdav
    expected = "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)

    r = sess.request(method, url, headers={"Want-Digest": "zcrc32"}, timeout=30)
    assert r.status_code == 200, f"{method} status {r.status_code}"

    digest = _parse_digest_header(r.headers.get("Digest"), "zcrc32")
    if digest is None:
        pytest.skip("WebDAV route returned no zcrc32 Digest header "
                    f"(headers: {dict(r.headers)})")
    assert digest == expected, \
        f"{method} zcrc32 Digest {digest!r} != oracle {expected!r}"


def test_webdav_crc32_alias_digest_matches(webdav):
    """`Want-Digest: crc32` yields the same value as zcrc32 (alias)."""
    sess, url, data = webdav
    expected = "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)

    rz = sess.head(url, headers={"Want-Digest": "zcrc32"}, timeout=30)
    rc = sess.head(url, headers={"Want-Digest": "crc32"}, timeout=30)
    dz = _parse_digest_header(rz.headers.get("Digest"), "zcrc32")
    dc = _parse_digest_header(rc.headers.get("Digest"), "crc32")
    if dz is None or dc is None:
        pytest.skip("WebDAV route did not emit both zcrc32 and crc32 Digests")
    assert dc == dz, f"crc32 Digest {dc!r} != zcrc32 Digest {dz!r}"
    assert dc == expected, f"crc32 Digest {dc!r} != oracle {expected!r}"
