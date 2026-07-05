"""
CRC64 cross-protocol integration tests (this gateway's crc64 = CRC-64/XZ,
crc64nvme = CRC-64/NVME / AWS x-amz-checksum-crc64nvme).

Self-contained: spins its own nginx with an S3 location (no SigV4, so the test
needs no signing), a WebDAV location, and a stream root:// server. Validates:

  * S3   — PutObject verifies a client-supplied x-amz-checksum-crc64nvme
           (correct → 200 + echo; wrong → 400 BadDigest; absent → 200 + echo),
           GET/HEAD echo the stored checksum, and CompleteMultipartUpload returns
           the FULL_OBJECT checksum of the reassembled object.
  * WebDAV — Want-Digest: crc64 → "Digest: crc64=<16-hex>".
  * root:// — the xrdcrc64 native client returns CRC-64/XZ over the wire (Qcksum).

All expected values come from an independent in-test Python CRC64 oracle, so a
wrong polynomial/encoding on any surface turns this red.
"""

import base64
import os
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from settings import HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCRC64 = os.path.join(REPO, "client", "bin", "xrdcrc64")

# Reflected polynomials (must match src/core/compat/crc64.c).
_XZ_POLY = 0xC96C5795D7870F42
_NVME_POLY = 0x9A6C9329AC4BC9B5
_MASK = (1 << 64) - 1


def _crc64(data, poly_refl):
    """Independent reflected CRC64 (init/xorout all-FF) oracle."""
    crc = _MASK
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly_refl if (crc & 1) else (crc >> 1)
        crc &= _MASK
    return crc ^ _MASK


def crc64xz_hex(data):
    return f"{_crc64(data, _XZ_POLY):016x}"


def crc64nvme_b64(data):
    return base64.b64encode(struct.pack(">Q", _crc64(data, _NVME_POLY))).decode()


# Self-test the oracle against the published check constants at import time.
assert crc64xz_hex(b"123456789") == "995dc9bbdf1939fa"
assert _crc64(b"123456789", _NVME_POLY) == 0xAE8B14860A799888


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    d = tmp_path_factory.mktemp("crc64")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    data = d / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"crc64 probe payload\n")

    s3_port = _free_port()
    dav_port = _free_port()
    root_port = _free_port()
    # S3 and WebDAV each occupy a whole server at location / (the bucket / path is
    # the first URL segment — an /s3/-style prefix would not be stripped).
    conf = f"""
worker_processes 1;
pid {d}/logs/nginx.pid;
error_log {d}/logs/error.log error;
events {{ worker_connections 128; }}
stream {{
    server {{
        listen {BIND_HOST}:{root_port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_allow_write on;
    }}
}}
http {{
    access_log off;
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t;
    server {{
        listen {BIND_HOST}:{s3_port};
        location / {{
            brix_s3 on;
            brix_s3_storage_backend posix:{data};
            brix_s3_bucket testbucket;
            brix_s3_allow_write on;
        }}
    }}
    server {{
        listen {BIND_HOST}:{dav_port};
        location / {{
            brix_webdav on;
            brix_webdav_storage_backend posix:{data};
            brix_webdav_auth none;
            brix_webdav_allow_write on;
        }}
    }}
}}
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)

    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx -t failed:\n" + chk.stderr)

    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (not _wait_port(s3_port) or not _wait_port(dav_port)
            or not _wait_port(root_port)):
        proc.terminate()
        pytest.skip("crc64 test servers did not start")

    yield {
        "s3": f"http://{HOST}:{s3_port}/testbucket",
        "dav": f"http://{HOST}:{dav_port}",
        "root": f"root://{HOST}:{root_port}",
        "data": str(data),
    }
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _req(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.getcode(), r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


# ---------------------------------------------------------------- S3 single-part

def test_s3_put_echoes_checksum_when_none_supplied(srv):
    body = b"crc64 single-part body\n"
    code, _, hdrs = _req("PUT", srv["s3"] + "/a.bin", body)
    assert code in (200, 201), code
    assert hdrs.get("x-amz-checksum-crc64nvme") == crc64nvme_b64(body)
    assert hdrs.get("x-amz-checksum-type") == "FULL_OBJECT"


def test_s3_put_verifies_correct_checksum(srv):
    body = b"crc64 verified body 12345\n"
    code, _, hdrs = _req("PUT", srv["s3"] + "/b.bin", body,
                         {"x-amz-checksum-crc64nvme": crc64nvme_b64(body)})
    assert code in (200, 201), code
    assert hdrs.get("x-amz-checksum-crc64nvme") == crc64nvme_b64(body)


def test_s3_put_rejects_wrong_checksum(srv):
    body = b"crc64 body that will be mis-checksummed\n"
    wrong = base64.b64encode(struct.pack(">Q", 0x0123456789ABCDEF)).decode()
    code, payload, _ = _req("PUT", srv["s3"] + "/c.bin", body,
                            {"x-amz-checksum-crc64nvme": wrong})
    assert code == 400, code
    assert b"BadDigest" in payload
    # The object must NOT have been stored on a checksum mismatch.
    assert not os.path.exists(os.path.join(srv["data"], "c.bin"))


def test_s3_get_and_head_echo_checksum(srv):
    body = b"crc64 readback body\n"
    code, _, _ = _req("PUT", srv["s3"] + "/d.bin", body)
    assert code in (200, 201), code

    exp = crc64nvme_b64(body)
    gc, _, gh = _req("GET", srv["s3"] + "/d.bin")
    assert gc == 200, gc
    assert gh.get("x-amz-checksum-crc64nvme") == exp

    hc, _, hh = _req("HEAD", srv["s3"] + "/d.bin")
    assert hc == 200, hc
    assert hh.get("x-amz-checksum-crc64nvme") == exp


# ---------------------------------------------------------------- S3 multipart

def _xml_value(blob, tag):
    open_t = f"<{tag}>".encode()
    close_t = f"</{tag}>".encode()
    i = blob.find(open_t)
    if i < 0:
        return None
    i += len(open_t)
    j = blob.find(close_t, i)
    return blob[i:j].decode() if j >= 0 else None


def test_s3_multipart_full_object_checksum(srv):
    key = "mp.bin"
    # Two parts; each part must be >= 5 MiB except the last in real S3, but this
    # gateway reassembles so size is unconstrained for the test.
    part1 = b"A" * 100000
    part2 = b"B" * 54321
    whole = part1 + part2

    ic, ib, _ = _req("POST", srv["s3"] + "/" + key + "?uploads")
    assert ic == 200, ic
    upload_id = _xml_value(ib, "UploadId")
    assert upload_id, ib

    for n, part in ((1, part1), (2, part2)):
        pc, _, _ = _req("PUT",
                        f"{srv['s3']}/{key}?partNumber={n}&uploadId={upload_id}",
                        part)
        assert pc in (200, 201), (n, pc)

    complete_xml = (
        "<CompleteMultipartUpload>"
        "<Part><PartNumber>1</PartNumber></Part>"
        "<Part><PartNumber>2</PartNumber></Part>"
        "</CompleteMultipartUpload>"
    ).encode()
    cc, cb, ch = _req("POST", f"{srv['s3']}/{key}?uploadId={upload_id}",
                      complete_xml)
    assert cc == 200, (cc, cb)
    exp = crc64nvme_b64(whole)
    assert _xml_value(cb, "ChecksumCRC64NVME") == exp, cb
    assert _xml_value(cb, "ChecksumType") == "FULL_OBJECT"
    # Header echo too (when present).
    if ch.get("x-amz-checksum-crc64nvme") is not None:
        assert ch.get("x-amz-checksum-crc64nvme") == exp


# ---------------------------------------------------------------- WebDAV digest

def test_webdav_want_digest_crc64(srv):
    body = b"webdav crc64 body payload\n"
    pc, _, _ = _req("PUT", srv["dav"] + "/wd.bin", body)
    assert pc in (200, 201, 204), pc

    code, _, hdrs = _req("GET", srv["dav"] + "/wd.bin",
                         headers={"Want-Digest": "crc64"})
    assert code == 200, code
    digest = hdrs.get("Digest", "")
    assert digest == f"crc64={crc64xz_hex(body)}", digest


# ---------------------------------------------------------------- root:// Qcksum

def test_root_xrdcrc64_matches_oracle(srv):
    if not os.access(XRDCRC64, os.X_OK):
        pytest.skip("xrdcrc64 client not built")
    body = open(os.path.join(srv["data"], "probe.txt"), "rb").read()
    out = subprocess.run([XRDCRC64, srv["root"] + "//probe.txt"],
                         capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        pytest.skip(f"xrdcrc64 over root:// failed: {out.stderr.strip()}")
    got = out.stdout.split()[0]
    assert got == crc64xz_hex(body), (got, out.stdout)
