"""
Phase-42 W2 — outbound (GET) compression NEGOTIATION gaps.

These tests cover the corners of Accept-Encoding negotiation and the
incompressible-MIME deny list that the existing roundtrip suites
(test_compression_outbound.py / test_compression_s3_outbound.py) do not:

  (1) QVAL-ZERO   — "gzip;q=0", "q=0.0", "q=0.00", "q=0.000" are exactly zero
                    (= refused → identity), while "q=0.5"/"q=1" select gzip.
                    (The negotiator was just fixed so the fractional-zero
                    spellings are correctly treated as a refusal.)
  (2) QVAL-MULTI  — multi-token Accept-Encoding ("br, gzip;q=0.9",
                    "gzip, zstd") selects a codec the server has, and
                    leading/trailing whitespace around tokens is tolerated.
  (3) HEAD        — a HEAD with Accept-Encoding: gzip never carries a body.
  (4) DENYLIST    — with a types{} block mapping .gz→application/gzip and
                    .jpg→image/jpeg, GETting incompressible-MIME objects with
                    Accept-Encoding: gzip yields NO Content-Encoding (identity),
                    because the server resolves content-type from the extension
                    BEFORE negotiating; a .txt/.bin compressible control object
                    still gets compressed.

Self-contained: launches its OWN minimal plain-HTTP nginx with
`xrootd_webdav_compress on` + a types{} block (using the project nginx binary),
so it never depends on the shared harness's config. Raw GETs go through urllib3
with decode_content=False so we observe the real wire encoding.
"""

import gzip
import os
import shutil
import socket
import subprocess
import time
import uuid

import pytest
import requests
import urllib3

from settings import NGINX_BIN

urllib3.disable_warnings()

WORK = os.path.join(os.environ["TMPDIR"], "xrd-cmp-neg")
_POOL = urllib3.PoolManager()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _write_conf(prefix, port, data_dir):
    # A types{} block so the negotiator can resolve content-type from the file
    # extension before deciding whether to compress. .gz/.jpg are on the
    # incompressible deny list (application/gzip, image/*); .txt/.bin map to
    # compressible types (or fall through to the default, which is compressible).
    conf = f"""
worker_processes 1;
error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_max_body_size 64m;
    default_type application/octet-stream;
    types {{
        text/plain               txt;
        application/octet-stream  bin;
        application/gzip          gz;
        image/jpeg                jpg;
    }}
    server {{
        listen {port};
        server_name localhost;
        location / {{
            root {data_dir};
            dav_methods DELETE MKCOL;
            xrootd_webdav on;
            xrootd_webdav_storage_backend posix:{data_dir};
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            xrootd_webdav_compress on;
        }}
    }}
}}
"""
    path = os.path.join(prefix, "nginx.conf")
    with open(path, "w") as fh:
        fh.write(conf)
    return path


@pytest.fixture(scope="module")
def base():
    if not os.path.isfile(NGINX_BIN) or not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not available: {NGINX_BIN}")
    shutil.rmtree(WORK, ignore_errors=True)
    data = os.path.join(WORK, "data")
    os.makedirs(data, exist_ok=True)
    os.makedirs(os.path.join(WORK, "logs"), exist_ok=True)
    port = _free_port()
    conf = _write_conf(WORK, port, data)

    chk = subprocess.run([NGINX_BIN, "-p", WORK, "-c", conf, "-t"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip(f"standalone nginx config rejected:\n{chk.stderr}")
    proc = subprocess.Popen([NGINX_BIN, "-p", WORK, "-c", conf, "-g", "daemon off;"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(url, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("standalone nginx did not come up")
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    shutil.rmtree(WORK, ignore_errors=True)


# A >256-byte highly-compressible payload (gzip-negotiation min size is 256).
def _payload(n=4096):
    return (b"the quick brown fox jumps over the lazy dog 0123456789\n"
            * (n // 54 + 1))[:n]


def _put(base, path, data):
    return requests.put(f"{base}{path}", data=data, timeout=60)


def _delete(base, path):
    try:
        requests.delete(f"{base}{path}", timeout=30)
    except Exception:
        pass


def _raw_get(base, path, headers):
    return _POOL.request("GET", f"{base}{path}", headers=headers,
                         decode_content=False, preload_content=True, retries=False)


def _name(tag, ext="bin"):
    return f"/neg_{tag}_{uuid.uuid4().hex}.{ext}"


# ---------------------------------------------------------------------------
# (1) QVAL-ZERO — fractional-zero q-values are a refusal; nonzero selects gzip.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("qval", ["gzip;q=0", "gzip;q=0.0", "gzip;q=0.00",
                                  "gzip;q=0.000"])
def test_qval_zero_is_identity(base, qval):
    """gzip with an exactly-zero q-value must NOT compress (identity body)."""
    data = _payload()
    path = _name("qz")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": qval})
        assert r.status == 200, f"{qval!r} status {r.status}"
        assert "Content-Encoding" not in r.headers, \
            f"{qval!r} should be identity, got {r.headers.get('Content-Encoding')!r}"
        assert r.data == data, f"{qval!r} body not byte-identical"
    finally:
        _delete(base, path)


@pytest.mark.parametrize("qval", ["gzip;q=0.5", "gzip;q=1", "gzip;q=1.0",
                                  "gzip;q=0.001"])
def test_qval_nonzero_selects_gzip(base, qval):
    """Any nonzero q-value (incl. q=0.001) selects gzip and compresses."""
    data = _payload()
    path = _name("qnz")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": qval})
        assert r.status == 200, f"{qval!r} status {r.status}"
        assert r.headers.get("Content-Encoding", "").lower() == "gzip", \
            f"{qval!r} should be gzip, got {r.headers.get('Content-Encoding')!r}"
        assert len(r.data) < len(data), f"{qval!r} not smaller"
        assert gzip.decompress(r.data) == data, f"{qval!r} body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (2) QVAL-MULTI — multi-token Accept-Encoding + whitespace tolerance.
# ---------------------------------------------------------------------------
# The server picks by a fixed preference (zstd > br > gzip > xz > deflate >
# bzip2 > lz4) intersected with what the client offered. We only assert the
# returned token is one the client actually offered and decodes byte-exact, so
# the test is robust to which optional codecs the build has.
_DECODERS = {
    "gzip": gzip.decompress,
}


def _decode(token, raw):
    if token in _DECODERS:
        return _DECODERS[token](raw)
    if token == "deflate":
        import zlib
        return zlib.decompress(raw)
    if token == "xz":
        import lzma
        return lzma.decompress(raw)
    if token == "bzip2":
        import bz2
        return bz2.decompress(raw)
    if token == "zstd":
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(raw)
        except Exception:
            pass
    # br, lz4, or zstd-without-python-module: shell out to the CLI.
    cli = {"br": ("brotli", ["-d", "-c"]),
           "lz4": ("lz4", ["-d", "-c"]),
           "zstd": ("zstd", ["-d", "-q", "-c"])}.get(token)
    if cli is None:
        pytest.skip(f"no decoder available for {token!r}")
    tool = shutil.which(cli[0])
    if tool is None:
        pytest.skip(f"{cli[0]} CLI not available to decode {token!r}")
    p = subprocess.run([tool, *cli[1]], input=raw, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=True)
    return p.stdout


@pytest.mark.parametrize("ae,offered", [
    ("br, gzip;q=0.9", {"br", "gzip"}),
    ("gzip, zstd", {"gzip", "zstd"}),
    ("   gzip   ,   zstd   ", {"gzip", "zstd"}),     # space whitespace around tokens
    (" br , gzip;q=0.9 ", {"br", "gzip"}),            # leading/trailing + inner spaces
])
def test_qval_multi_selects_offered_codec(base, ae, offered):
    """A multi-token Accept-Encoding selects one of the offered codecs and the
    body decodes byte-exact; surrounding whitespace is tolerated."""
    data = _payload()
    path = _name("multi")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": ae})
        assert r.status == 200, f"{ae!r} status {r.status}"
        enc = r.headers.get("Content-Encoding", "").lower()
        assert enc in offered, \
            f"{ae!r}: Content-Encoding {enc!r} not in offered {offered}"
        assert len(r.data) < len(data), f"{ae!r}: body not smaller"
        assert _decode(enc, r.data) == data, f"{ae!r}: {enc} body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


def test_qval_multi_tab_whitespace_tolerated(base):
    """RFC 7230 OWS permits HTAB (as well as SP) around Accept-Encoding list
    members. accept_encoding_has() now skips/trims both SP and HTAB, so a
    tab-delimited/-prefixed Accept-Encoding ("\\tbr ,\\tgzip;q=0.9\\t") is parsed
    and a codec is selected (regression test for the OWS-handling fix)."""
    data = _payload()
    path = _name("tabws")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "\tbr ,\tgzip;q=0.9\t"})
        assert r.status == 200
        enc = r.headers.get("Content-Encoding", "").lower()
        assert enc in {"br", "gzip"}, \
            f"tab-OWS Accept-Encoding ignored, CE={enc!r}"
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (3) HEAD never carries a body even when compression is negotiable.
# ---------------------------------------------------------------------------
def test_head_with_accept_encoding_has_no_body(base):
    data = _payload()
    path = _name("head")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _POOL.request("HEAD", f"{base}{path}",
                          headers={"Accept-Encoding": "gzip"},
                          decode_content=False, preload_content=True,
                          retries=False)
        assert r.status == 200, f"HEAD status {r.status}"
        assert r.data == b"", f"HEAD body should be empty, got {len(r.data)} bytes"
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (4) DENYLIST-MIME — content-type resolved from extension BEFORE negotiation.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ext", ["gz", "jpg"])
def test_incompressible_mime_not_compressed(base, ext):
    """An object whose extension maps (via types{}) to an already-compressed
    MIME type (.gz→application/gzip, .jpg→image/jpeg) must be served identity
    even when the client offers gzip."""
    data = os.urandom(2048)        # >256 bytes; random => CE would shrink little
    path = _name("deny", ext=ext)
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200, f".{ext} status {r.status}"
        assert "Content-Encoding" not in r.headers, \
            f".{ext} should be identity, got {r.headers.get('Content-Encoding')!r}"
        assert r.data == data, f".{ext} body not byte-identical"
    finally:
        _delete(base, path)


@pytest.mark.parametrize("ext", ["txt", "bin"])
def test_compressible_mime_control_is_compressed(base, ext):
    """Control: a .txt (text/plain) / .bin (application/octet-stream) object is
    a compressible MIME type, so gzip IS applied (proves the deny list is
    selective, not blanket)."""
    data = _payload()
    path = _name("ctl", ext=ext)
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200, f".{ext} status {r.status}"
        assert r.headers.get("Content-Encoding", "").lower() == "gzip", \
            f".{ext} should be gzip, got {r.headers.get('Content-Encoding')!r}"
        assert len(r.data) < len(data), f".{ext} not smaller"
        assert gzip.decompress(r.data) == data, f".{ext} body mismatch"
    finally:
        _delete(base, path)
