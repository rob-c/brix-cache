"""Protocol-labelled HTTP access logging.

The module exposes $brix_protocol so nginx's native access_log can write a
single HTTP access log tagged with webdav/s3 without duplicate module-side log
lines.
"""

from pathlib import Path
import time
import uuid

import pytest
import requests


BUCKET = "testbucket"


@pytest.fixture()
def http_access_log(test_env):
    return Path(test_env["log_dir"]) / "http_access.log"


def _start_offset(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def _wait_for_log(path: Path, offset: int, *needles: str) -> str:
    deadline = time.time() + 5
    last = ""

    while time.time() < deadline:
        if path.exists():
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                last = fh.read()
            if all(needle in last for needle in needles):
                return last
        time.sleep(0.05)

    assert False, f"missing log markers {needles}; recent log chunk:\n{last}"


@pytest.mark.requires_local_server
def test_webdav_success_access_log_has_protocol_label(test_env, http_access_log):
    uid = uuid.uuid4().hex
    path = f"/log_webdav_{uid}.txt"
    offset = _start_offset(http_access_log)

    r = requests.put(f"{test_env['http_webdav_url']}{path}",
                     data=b"log protocol probe", timeout=10)
    assert r.status_code in (200, 201)

    r = requests.get(f"{test_env['http_webdav_url']}{path}", timeout=10)
    assert r.status_code == 200

    # phase-106 W1: the SAME shared log_format carries the full $brix_* set on
    # every plane. On a served webdav GET the fields resolve to real values
    # (tls off on the cleartext listener, tier=posix, anonymous auth), not the
    # sentinel — proving one log_format works across planes at runtime.
    line = _wait_for_log(http_access_log, offset, f"GET {path} HTTP/1.1",
                         "proto=webdav", "tls=off", "tier=posix")
    assert "cache=" in line and "am=" in line, line


@pytest.mark.requires_local_server
def test_webdav_error_access_log_has_protocol_label(test_env, http_access_log):
    uid = uuid.uuid4().hex
    path = f"/missing_log_webdav_{uid}.bin"
    offset = _start_offset(http_access_log)

    r = requests.get(f"{test_env['http_webdav_url']}{path}", timeout=10)
    assert r.status_code == 404

    _wait_for_log(http_access_log, offset, f"GET {path} HTTP/1.1",
                  " 404 ", "proto=webdav")


@pytest.mark.requires_local_server
def test_s3_security_negative_access_log_has_protocol_label(test_env,
                                                           http_access_log):
    uid = uuid.uuid4().hex
    dst_key = f"log_s3_copy_traversal_{uid}.txt"
    offset = _start_offset(http_access_log)

    r = requests.put(
        f"{test_env['s3_url']}/{BUCKET}/{dst_key}",
        headers={"x-amz-copy-source": f"/{BUCKET}/../../../etc/passwd"},
        timeout=10,
    )
    assert r.status_code in (400, 403)

    # phase-106 W1: the identical log_format works unchanged on the s3 plane —
    # the cross-plane claim, proven on a second real protocol.
    line = _wait_for_log(http_access_log, offset,
                         f"PUT /{BUCKET}/{dst_key} HTTP/1.1",
                         "proto=s3", "tls=", "tier=", "cache=")
    assert "am=" in line and "vo=" in line, line
