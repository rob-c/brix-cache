"""
test_audit15c_zip_cd_caps.py — the ZIP central-directory bomb caps
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15:
`brix_zip_cd_max_bytes` and `brix_zip_cd_max_bytes` had zero coverage
on either plane).

The cap is enforced in the shared kernel (zip_kernel.c: cd_size > cd_max →
ECORRUPT) before the central directory is ever parsed — the zip-bomb guard.
A 4-member STORED zip has a CD well over the configured 64 bytes, so the
capped stream listener and the capped WebDAV location must refuse member
access while their uncapped twins serve the identical file, pinning the
refusal to the cap directive rather than to zip-member access itself.
"""

import io
import zipfile

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST
from test_phase25_ratelimit import (KXR_OK, _xrd_login, _xrd_open, _xrd_read)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15c-zipcaps")]

KXR_ERROR = 4003
MEMBER = b"zip-cap-member-payload\n"


def _build_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("member-0.txt", MEMBER)
        for i in range(1, 4):
            z.writestr(f"filler-{i}.txt", f"filler payload {i}\n")
    return buf.getvalue()


@pytest.fixture()
def zipcaps(lifecycle, tmp_path):
    data = tmp_path / "data"
    (data / "capped").mkdir(parents=True)
    blob = _build_zip()
    (data / "big.zip").write_bytes(blob)
    (data / "capped" / "big.zip").write_bytes(blob)
    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15c-zipcaps",
        template="nginx_audit15c_zipcaps.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST},
        reason="audit-15c ZIP central-directory caps"))


def test_capped_stream_refuses_member_open(zipcaps):
    s = _xrd_login(HOST, zipcaps.port)
    try:
        status, body = _xrd_open(s, "/big.zip?xrdcl.unzip=member-0.txt")
        assert status == KXR_ERROR, \
            f"CD over brix_zip_cd_max_bytes was admitted: {status} {body!r}"
    finally:
        s.close()


def test_uncapped_stream_serves_member(zipcaps):
    s = _xrd_login(HOST, zipcaps.extra_ports["CTRL_PORT"])
    try:
        status, body = _xrd_open(s, "/big.zip?xrdcl.unzip=member-0.txt")
        assert status == KXR_OK, (status, body)
        status, data = _xrd_read(s, body[:4], 0, len(MEMBER))
        assert status == KXR_OK and data == MEMBER, (status, data)
    finally:
        s.close()


def test_capped_http_location_refuses(zipcaps):
    port = zipcaps.extra_ports["HTTP_PORT"]
    r = requests.get(f"http://{HOST}:{port}/capped/big.zip",
                     params={"xrdcl.unzip": "member-0.txt"}, timeout=10)
    assert r.status_code >= 400, (r.status_code, r.content[:80])


def test_uncapped_http_location_serves(zipcaps):
    port = zipcaps.extra_ports["HTTP_PORT"]
    r = requests.get(f"http://{HOST}:{port}/big.zip",
                     params={"xrdcl.unzip": "member-0.txt"}, timeout=10)
    assert r.status_code == 200, (r.status_code, r.content[:80])
    assert r.content == MEMBER
