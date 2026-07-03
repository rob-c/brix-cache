"""
Large-file correctness and metrics integration tests (Section 12).

Exercises the 200 MiB test file (DATA_ROOT/large200.bin) pre-seeded by conftest.
Verifies:
  12a — xrdcp download preserves bytes AND drives bytes_tx_total into [200, 220] MiB
  12b — xrdcp upload preserves bytes AND drives bytes_rx_total into [200, 220] MiB
  12c — WebDAV curl PUT+GET round-trip is byte-exact
  12d — S3 PutObject+GetObject is byte-exact
  12e — CRC32c checksum reported by server matches locally computed value

All tests are marked slow, large, and requires_local_server.
Run with: pytest tests/test_large_file_metrics.py -v -m large
"""

import hashlib
import os
import re
import subprocess
import tempfile
import urllib.request
import uuid

import pytest
import requests

from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_METRICS_PORT,
    NGINX_S3_PORT,
    XRDCP_BIN,
    XRDFS_BIN,
)

pytestmark = [
    pytest.mark.slow,
    pytest.mark.large,
    pytest.mark.requires_local_server,
]

MiB    = 1024 * 1024
BUCKET = "testbucket"

# ---------------------------------------------------------------------------
# Module-level constants (overwritten by autouse fixture)
# ---------------------------------------------------------------------------

METRICS_URL = f"http://{HOST}:{NGINX_METRICS_PORT}/metrics"
ANON_PORT   = str(NGINX_ANON_PORT)
ANON_URL    = f"root://{HOST}:{NGINX_ANON_PORT}"
HTTP_WEBDAV = f"http://{HOST}:{NGINX_HTTP_WEBDAV_PORT}"
S3_BASE     = f"http://{HOST}:{NGINX_S3_PORT}"
LARGE_FILE  = os.path.join(DATA_ROOT, "large200.bin")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch() -> str:
    with urllib.request.urlopen(METRICS_URL, timeout=10) as r:
        return r.read().decode()


def _parse(text: str, name: str, labels: dict) -> int:
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        m = re.match(r"^" + re.escape(name) + r"\{([^}]*)\}\s+(\d+)", line)
        if not m:
            continue
        block, val = m.group(1), m.group(2)
        if all(f'{k}="{v}"' in block for k, v in labels.items()):
            return int(val)
    return -1


def _scalar(text: str, name: str) -> int:
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "\t"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                pass
    return -1


def _delta(before: str, after: str, name: str,
           labels: dict | None = None) -> int:
    if labels is not None:
        v_b = _parse(before, name, labels)
        v_a = _parse(after,  name, labels)
    else:
        v_b = _scalar(before, name)
        v_a = _scalar(after,  name)
    if v_b == -1:
        v_b = 0
    return max(0, v_a - v_b)


def _md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _known_md5() -> str:
    """Return MD5 of large200.bin from env (set by conftest) or recompute."""
    md5 = os.environ.get("LARGE_FILE_MD5")
    if md5:
        return md5
    return _md5_file(LARGE_FILE)


def _skip_if_missing():
    if not os.path.exists(LARGE_FILE):
        pytest.skip("large200.bin not present in data root — conftest did not create it")


# ---------------------------------------------------------------------------
# Section 12a — 200 MB xrdcp download: byte-exact + bytes_tx delta in [200, 220] MiB
# ---------------------------------------------------------------------------

@pytest.mark.timeout(300)
def test_xrdcp_200mb_download_bytes_tx_delta():
    """xrdcp download of large200.bin: MD5 preserved, bytes_tx_total delta in [200, 220] MiB."""
    _skip_if_missing()
    known_md5 = _known_md5()

    before = _fetch()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as out:
        out_path = out.name
    try:
        rc = subprocess.run(
            [XRDCP_BIN, "-f", f"{ANON_URL}//large200.bin", out_path],
            capture_output=True, timeout=240,
        ).returncode
        assert rc == 0, "xrdcp download of large200.bin failed"
        assert _md5_file(out_path) == known_md5, "large200.bin MD5 mismatch after xrdcp download"
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)

    after = _fetch()
    delta = _delta(before, after, "brix_bytes_tx_total",
                   {"port": ANON_PORT, "auth": "anon"})
    assert delta >= 200 * MiB, (
        f"bytes_tx_total delta {delta // MiB} MiB < 200 MiB after large file download"
    )
    assert delta <= 220 * MiB, (
        f"bytes_tx_total delta {delta // MiB} MiB > 220 MiB — possible double-counting"
    )


# ---------------------------------------------------------------------------
# Section 12b — 200 MB xrdcp upload: byte-exact + bytes_rx delta in [200, 220] MiB
# ---------------------------------------------------------------------------

@pytest.mark.timeout(300)
def test_xrdcp_200mb_upload_bytes_rx_delta():
    """xrdcp upload of large200.bin: file arrives intact, bytes_rx_total delta in [200, 220] MiB."""
    _skip_if_missing()
    known_md5 = _known_md5()

    dst_name = f"large_upload_{uuid.uuid4().hex[:8]}.bin"
    dst_path = os.path.join(os.path.dirname(LARGE_FILE), dst_name)

    before = _fetch()
    rc = subprocess.run(
        [XRDCP_BIN, "-f", LARGE_FILE, f"{ANON_URL}//{dst_name}"],
        capture_output=True, timeout=240,
    ).returncode
    assert rc == 0, "xrdcp upload of large200.bin failed"

    after = _fetch()
    delta = _delta(before, after, "brix_bytes_rx_total",
                   {"port": ANON_PORT, "auth": "anon"})
    assert delta >= 200 * MiB, (
        f"bytes_rx_total delta {delta // MiB} MiB < 200 MiB after large file upload"
    )
    assert delta <= 220 * MiB, (
        f"bytes_rx_total delta {delta // MiB} MiB > 220 MiB — possible double-counting"
    )

    # Verify the uploaded file matches the source when the data dir is accessible.
    if os.path.exists(dst_path):
        assert _md5_file(dst_path) == known_md5, "Uploaded large200.bin MD5 mismatch on disk"


# ---------------------------------------------------------------------------
# Section 12c — Large WebDAV PUT then GET byte-exact
# ---------------------------------------------------------------------------

@pytest.mark.timeout(300)
def test_webdav_large_put_get_byte_exact():
    """curl PUT large200.bin to WebDAV, then GET back: MD5 must match."""
    _skip_if_missing()
    known_md5 = _known_md5()

    remote_path = f"/large_webdav_{uuid.uuid4().hex[:8]}.bin"
    url = f"{HTTP_WEBDAV}{remote_path}"

    put = subprocess.run(
        ["curl", "-sf", "-T", LARGE_FILE, url],
        capture_output=True, timeout=240,
    )
    assert put.returncode == 0, f"curl PUT large file failed: {put.stderr.decode()!r}"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as out:
        out_path = out.name
    try:
        get = subprocess.run(
            ["curl", "-sf", "-o", out_path, url],
            capture_output=True, timeout=240,
        )
        assert get.returncode == 0, f"curl GET large file failed: {get.stderr.decode()!r}"
        assert _md5_file(out_path) == known_md5, "WebDAV large file GET MD5 mismatch"
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)


# ---------------------------------------------------------------------------
# Section 12d — Large S3 PutObject then GetObject byte-exact
# ---------------------------------------------------------------------------

@pytest.mark.timeout(300)
def test_s3_large_putobject_byte_exact():
    """S3 PUT large200.bin, then GET back: MD5 must match."""
    _skip_if_missing()
    known_md5 = _known_md5()

    key = f"large_s3_{uuid.uuid4().hex[:8]}.bin"
    url = f"{S3_BASE}/{BUCKET}/{key}"

    with open(LARGE_FILE, "rb") as fh:
        resp = requests.put(url, data=fh, timeout=240)
    assert resp.status_code == 200, f"S3 PUT large file returned {resp.status_code}"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as out:
        out_path = out.name
    try:
        resp = requests.get(url, timeout=240, stream=True)
        assert resp.status_code == 200, f"S3 GET large file returned {resp.status_code}"
        with open(out_path, "wb") as f:
            for chunk in resp.iter_content(65536):
                f.write(chunk)
        assert _md5_file(out_path) == known_md5, "S3 large file GET MD5 mismatch"
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)


# ---------------------------------------------------------------------------
# Section 12e — CRC32c checksum reported by server matches local computation
# ---------------------------------------------------------------------------

@pytest.mark.timeout(60)
def test_crc32c_checksum_matches_local_computation():
    """xrdfs query checksum reports crc32c matching locally computed value."""
    crc32c = pytest.importorskip("crc32c")
    _skip_if_missing()

    # Streaming CRC32c to avoid loading 200 MiB into memory.
    value = 0
    with open(LARGE_FILE, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            value = crc32c.crc32c(chunk, value)
    expected_hex = format(value & 0xFFFFFFFF, "08x")

    res = subprocess.run(
        [XRDFS_BIN, ANON_URL, "query", "checksum", "crc32c //large200.bin"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 0, f"xrdfs query checksum failed: {res.stderr}"

    # Server output may be "crc32c HEXVALUE" or "crc32c:HEXVALUE".
    output = res.stdout.strip().lower()
    server_hex = None
    for token in output.split():
        if token.startswith("crc32c:"):
            server_hex = token.split(":", 1)[1]
            break
    if server_hex is None:
        parts = output.split()
        for i, part in enumerate(parts):
            if "crc32c" in part and i + 1 < len(parts):
                server_hex = parts[i + 1]
                break

    assert server_hex is not None, (
        f"Could not parse crc32c value from xrdfs output: {res.stdout!r}"
    )
    assert server_hex == expected_hex, (
        f"CRC32c mismatch: server={server_hex} local={expected_hex}"
    )
