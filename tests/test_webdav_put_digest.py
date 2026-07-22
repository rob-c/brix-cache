"""WebDAV PUT ingest-digest verification (src/protocols/webdav/put_body.c
webdav_put_verify_ingest_digest + webdav_digest_select).

Exercises the client->server body-integrity branches over a plain-HTTP WebDAV
listener: a correct RFC-3230 Digest (base64 md5/sha-256, hex crc32) and the
Content-MD5 fallback commit; a wrong or malformed value is refused with 400; an
unsupported alg is skipped (best-effort interop); a Content-Encoding'd body
skips verification; and under brix_webdav_require_digest a bare PUT is 400.

Reuses nginx_lc_checksum_on_write.conf (write-enabled anon WebDAV, EXTRA_DIRECTIVES
slot) via the lifecycle harness — the same instance family the checksum-on-write
suite uses, but here the digest headers drive the *verify* path (which runs on
every PUT regardless of checksum-on-write).
"""

import base64
import gzip
import hashlib
import os
import uuid
import zlib

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

BODY = b"ingest-digest-verification-body-0123456789"
OK = (200, 201, 204)


def _start(lifecycle, name, extra=""):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_checksum_on_write.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST, "EXTRA_DIRECTIVES": extra},
        reason="WebDAV PUT ingest-digest verification"))
    return f"http://{HOST}:{ep.port}"


@pytest.fixture()
def put_server(lifecycle):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    return _start(lifecycle, "lc-put-digest")


@pytest.fixture()
def require_server(lifecycle):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    return _start(lifecycle, "lc-put-require-digest",
                  extra="brix_webdav_require_digest on;")


def _md5_b64(b):
    return base64.b64encode(hashlib.md5(b).digest()).decode()


def _sha256_b64(b):
    return base64.b64encode(hashlib.sha256(b).digest()).decode()


def _crc32_hex(b):
    return format(zlib.crc32(b) & 0xffffffff, "08x")


def _put(base, headers):
    name = f"digest_{uuid.uuid4().hex}.bin"
    return requests.put(f"{base}/{name}", data=BODY, headers=headers, timeout=10)


# --------------------------------------------------------------------------- #
# Success — a correct asserted digest commits                                  #
# --------------------------------------------------------------------------- #

def test_correct_md5_commits(put_server):
    r = _put(put_server, {"Digest": f"md5={_md5_b64(BODY)}"})
    assert r.status_code in OK, r.text


def test_correct_sha256_commits(put_server):
    r = _put(put_server, {"Digest": f"sha-256={_sha256_b64(BODY)}"})
    assert r.status_code in OK, r.text


def test_correct_crc32_hex_commits(put_server):
    r = _put(put_server, {"Digest": f"crc32={_crc32_hex(BODY)}"})
    assert r.status_code in OK, r.text


def test_crc32_hex_case_insensitive_commits(put_server):
    r = _put(put_server, {"Digest": f"crc32={_crc32_hex(BODY).upper()}"})
    assert r.status_code in OK, r.text


def test_content_md5_fallback_commits(put_server):
    r = _put(put_server, {"Content-MD5": _md5_b64(BODY)})
    assert r.status_code in OK, r.text


def test_unknown_alg_skipped_commits(put_server):
    r = _put(put_server, {"Digest": "whirlpool=deadbeef"})
    assert r.status_code in OK, r.text


def test_wrong_digest_but_content_encoding_skips_verify(put_server):
    # A coded body is stored decoded; a digest over the encoded stream cannot be
    # checked, so verification is skipped even though the value is wrong. Send a
    # genuinely gzip-coded body so the Content-Encoding is legitimate.
    coded = gzip.compress(BODY)
    name = f"digest_{uuid.uuid4().hex}.bin"
    r = requests.put(f"{put_server}/{name}", data=coded,
                     headers={"Digest": f"md5={_md5_b64(b'WRONG')}",
                              "Content-Encoding": "gzip"}, timeout=10)
    assert r.status_code in OK, r.text


# --------------------------------------------------------------------------- #
# Error — a wrong or malformed asserted digest is refused                      #
# --------------------------------------------------------------------------- #

def test_wrong_md5_rejected(put_server):
    r = _put(put_server, {"Digest": f"md5={_md5_b64(b'a different body')}"})
    assert r.status_code == 400, r.text


def test_malformed_digest_value_rejected(put_server):
    r = _put(put_server, {"Digest": "md5=@@not-base64@@"})
    assert r.status_code == 400, r.text


def test_wrong_crc32_hex_rejected(put_server):
    r = _put(put_server, {"Digest": "crc32=00000000"})
    assert r.status_code == 400, r.text


# --------------------------------------------------------------------------- #
# require_digest — a PUT with no usable digest is refused                       #
# --------------------------------------------------------------------------- #

def test_require_digest_missing_rejected(require_server):
    r = _put(require_server, {})
    assert r.status_code == 400, r.text


def test_require_digest_correct_commits(require_server):
    r = _put(require_server, {"Digest": f"md5={_md5_b64(BODY)}"})
    assert r.status_code in OK, r.text
