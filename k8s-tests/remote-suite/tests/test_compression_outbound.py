"""
Phase-42 W2 — outbound (GET) response compression.

Self-contained: this test launches its OWN minimal plain-HTTP nginx instance with
`brix_compress on` (using the project nginx binary), so it exercises
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
            brix_storage_backend posix:{data_dir};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_compress on;
        }}
    }}
}}
"""
    path = os.path.join(prefix, "nginx.conf")
    with open(path, "w") as fh:
        fh.write(conf)
    return path


def _require_nginx_binary():
    if not os.path.isfile(NGINX_BIN) or not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not available: {NGINX_BIN}")


def _validate_config(conf):
    check = subprocess.run([NGINX_BIN, "-p", WORK, "-c", conf, "-t"],
                           capture_output=True, text=True)
    if check.returncode != 0:
        pytest.skip(f"standalone nginx config rejected:\n{check.stderr}")


def _wait_for_http(proc, url):
    for _ in range(50):
        try:
            requests.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.1)
    proc.terminate()
    pytest.fail("standalone nginx did not come up")


def _stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


@pytest.fixture(scope="module")
def base():
    _require_nginx_binary()
    shutil.rmtree(WORK, ignore_errors=True)
    data = os.path.join(WORK, "data")
    os.makedirs(data, exist_ok=True)
    os.makedirs(os.path.join(WORK, "logs"), exist_ok=True)
    port = _free_port()
    conf = _write_conf(WORK, port, data)

    _validate_config(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", WORK, "-c", conf, "-g", "daemon off;"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    _wait_for_http(proc, url)
    yield url
    _stop_server(proc)
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


def _assert_compressed_response(response, token, data, decompress):
    assert response.status == 200, f"{token} GET status {response.status}"
    encoding = response.headers.get("Content-Encoding", "")
    assert encoding.lower() == token, f"{token}: Content-Encoding={encoding!r}"
    raw = response.data
    assert len(raw) < len(data), f"{token}: not smaller ({len(raw)})"
    assert decompress(raw) == data, f"{token}: body mismatch"
    assert "accept-encoding" in response.headers.get("Vary", "").lower()


@pytest.mark.parametrize("token", list(CODECS))
def test_get_compressed_roundtrip(base, token):
    decompress = CODECS[token]
    data = _payload()
    path = f"/out_{token.replace('/', '')}_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        response = _raw_get(base, path, {"Accept-Encoding": token})
        _assert_compressed_response(response, token, data, decompress)
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
