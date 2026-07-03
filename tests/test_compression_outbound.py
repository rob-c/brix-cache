"""
Phase-42 W2 — outbound (GET) response compression.

Self-contained: this test launches its OWN minimal plain-HTTP nginx instance with
`brix_webdav_compress on` (using the project nginx binary), so it exercises
outbound compression without depending on the shared test harness's config (where
enabling compression globally would make every GET chunked and break unrelated
Content-Length assertions).

For every codec the server can emit (gzip, deflate, zstd, xz, brotli, bzip2): PUT
a compressible object uncompressed, GET it advertising ONLY that codec, and assert
the response carries `Content-Encoding: <token>` + `Vary` and that the raw
(undecoded) body decompresses byte-exact. Plus negotiation guards (no
Accept-Encoding / tiny file / Range -> identity).
"""

import bz2
import gzip
import lzma
import os
import shutil
import socket
import subprocess
import time
import uuid
import zlib

import pytest
import requests
import urllib3

from settings import NGINX_BIN

urllib3.disable_warnings()

WORK = os.path.join(os.environ["TMPDIR"], "xrd-cmp-out")
_POOL = urllib3.PoolManager()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _write_conf(prefix, port, data_dir):
    conf = f"""
worker_processes 1;
error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_max_body_size 256m;
    server {{
        listen {port};
        server_name localhost;
        location / {{
            root {data_dir};
            dav_methods DELETE MKCOL;
            brix_webdav on;
            brix_webdav_storage_backend posix:{data_dir};
            brix_webdav_auth none;
            brix_webdav_allow_write on;
            brix_webdav_compress on;
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


def _decompress_cli(tool, args, data):
    path = shutil.which(tool)
    if path is None:
        pytest.skip(f"{tool} not available to decode test payload")
    p = subprocess.run([path, *args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=True)
    return p.stdout


def d_gzip(b):    return gzip.decompress(b)
def d_deflate(b): return zlib.decompress(b)
def d_xz(b):      return lzma.decompress(b)
def d_bzip2(b):   return bz2.decompress(b)


def d_zstd(b):
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompress(b)
    except Exception:
        return _decompress_cli("zstd", ["-d", "-q", "-c"], b)


def d_brotli(b):
    try:
        import brotli
        return brotli.decompress(b)
    except Exception:
        return _decompress_cli("brotli", ["-d", "-c"], b)


def d_lz4(b):
    # no python lz4 module in this env — decode via the lz4 CLI (LZ4 Frame)
    return _decompress_cli("lz4", ["-d", "-c"], b)


CODECS = {
    "gzip": d_gzip, "deflate": d_deflate, "zstd": d_zstd,
    "xz": d_xz, "br": d_brotli, "bzip2": d_bzip2, "lz4": d_lz4,
}


def _payload(n=200_000):
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


@pytest.mark.parametrize("token", list(CODECS))
def test_get_compressed_roundtrip(base, token):
    decompress = CODECS[token]
    data = _payload()
    path = f"/out_{token.replace('/', '')}_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": token})
        assert r.status == 200, f"{token} GET status {r.status}"
        enc = r.headers.get("Content-Encoding", "")
        assert enc.lower() == token, f"{token}: Content-Encoding={enc!r}"
        raw = r.data
        assert len(raw) < len(data), f"{token}: not smaller ({len(raw)})"
        assert decompress(raw) == data, f"{token}: body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


def test_no_accept_encoding_is_identity(base):
    data = _payload()
    path = f"/out_none_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {})
        assert r.status == 200 and "Content-Encoding" not in r.headers
        assert r.data == data
    finally:
        _delete(base, path)


def test_small_file_not_compressed(base):
    data = b"tiny"
    path = f"/out_tiny_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200 and "Content-Encoding" not in r.headers
        assert r.data == data
    finally:
        _delete(base, path)


def test_range_request_not_compressed(base):
    data = _payload()
    path = f"/out_range_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip", "Range": "bytes=0-99"})
        assert r.status == 206, f"range status {r.status}"
        assert "Content-Encoding" not in r.headers
        assert r.data == data[:100]
    finally:
        _delete(base, path)
