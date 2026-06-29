"""S3 multi-algorithm full-object checksums (phase-43 W1).

Covers the AWS checksum set beyond CRC-64/NVME — CRC32, CRC32C, SHA-1, SHA-256:
  - upload verify (matching value → 200 + echo; mismatch → 400 BadDigest, no object)
  - ambiguous/unsupported selection → 400 InvalidRequest, no object
  - x-amz-sdk-checksum-algorithm declaration (value-less) → compute + echo
  - GET/HEAD echo gated by x-amz-checksum-mode: ENABLED
  - the historical crc64nvme default is preserved when no checksum is requested

Uses the pre-started nginx_shared instance (port 9001), anonymous + write.
"""

import base64
import glob
import hashlib
import os
import time
import uuid
import zlib

import pytest
import requests

from settings import S3_BUCKET, TEST_ROOT

BUCKET = S3_BUCKET
DATA = b"the quick brown fox jumps over the lazy dog" * 7


def _b64(b):
    return base64.b64encode(b).decode()


# crc32c (Castagnoli) reference, used only if the algorithm is exercised.
def _crc32c(data):
    poly = 0x82F63B78
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


CHECKSUMS = {
    "crc32": _b64((zlib.crc32(DATA) & 0xFFFFFFFF).to_bytes(4, "big")),
    "crc32c": _b64(_crc32c(DATA).to_bytes(4, "big")),
    "sha1": _b64(hashlib.sha1(DATA).digest()),
    "sha256": _b64(hashlib.sha256(DATA).digest()),
}


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _key(s3_url):
    return f"{s3_url}/{BUCKET}/cksum_{uuid.uuid4().hex}"


def _find_audit_line(token, kind="stage", timeout=5.0):
    """Poll every xfer_audit.log under the test root for a line with token+kind."""
    audit = set(glob.glob(os.path.join(TEST_ROOT, "**", "xfer_audit.log"),
                          recursive=True))
    audit.add(os.path.join(TEST_ROOT, "logs", "xfer_audit.log"))
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in audit:
            try:
                with open(p, "r", errors="replace") as fh:
                    for line in fh:
                        if token in line and f"kind={kind}" in line:
                            return line
            except OSError:
                pass
        time.sleep(0.2)
    return None


def test_put_emits_unified_stage_audit(s3_url):
    """An S3 PutObject (chunked/aio commit path) emits the SAME unified stage
    audit line as WebDAV/root:// uploads — closing the prior gap where S3 PUT
    committed via the raw staged primitive without an audit record."""
    k = _key(s3_url)
    key_name = k.rsplit("/", 1)[-1]            # cksum_<uuid> = the object filename
    r = requests.put(k, data=DATA, timeout=10)
    assert r.status_code == 200, r.text

    line = _find_audit_line(key_name, kind="stage")
    requests.delete(k, timeout=10)
    assert line is not None, "no unified kind=stage audit line for the S3 PUT"
    assert "dir=in" in line
    assert "result=ok" in line
    assert f"bytes={len(DATA)}" in line


# ---------------------------------------------------------------------------
# Upload verify + echo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo", ["crc32", "crc32c", "sha1", "sha256"])
def test_put_checksum_match_echoes(s3_url, algo):
    k = _key(s3_url)
    hdr = f"x-amz-checksum-{algo}"
    r = requests.put(k, data=DATA, headers={hdr: CHECKSUMS[algo]}, timeout=10)
    assert r.status_code == 200, r.text
    assert r.headers.get(hdr) == CHECKSUMS[algo]
    assert r.headers.get("x-amz-checksum-type") == "FULL_OBJECT"
    requests.delete(k, timeout=10)


@pytest.mark.parametrize("algo", ["crc32", "sha256"])
def test_put_checksum_mismatch_400_no_object(s3_url, algo):
    k = _key(s3_url)
    hdr = f"x-amz-checksum-{algo}"
    width = 4 if algo.startswith("crc") else (20 if algo == "sha1" else 32)
    bad = _b64(b"\x00" * width)
    r = requests.put(k, data=DATA, headers={hdr: bad}, timeout=10)
    assert r.status_code == 400
    assert "BadDigest" in r.text
    assert requests.head(k, timeout=10).status_code == 404  # object not kept


# ---------------------------------------------------------------------------
# Conflicting / unsupported selection
# ---------------------------------------------------------------------------


def test_put_conflicting_checksums_400(s3_url):
    k = _key(s3_url)
    r = requests.put(
        k,
        data=DATA,
        headers={
            "x-amz-checksum-sha256": CHECKSUMS["sha256"],
            "x-amz-checksum-crc32": CHECKSUMS["crc32"],
        },
        timeout=10,
    )
    assert r.status_code == 400
    assert "InvalidRequest" in r.text
    assert requests.head(k, timeout=10).status_code == 404


def test_put_value_disagrees_with_declared_algo_400(s3_url):
    k = _key(s3_url)
    r = requests.put(
        k,
        data=DATA,
        headers={
            "x-amz-sdk-checksum-algorithm": "CRC32",
            "x-amz-checksum-sha256": CHECKSUMS["sha256"],
        },
        timeout=10,
    )
    assert r.status_code == 400
    assert "InvalidRequest" in r.text


def test_put_unsupported_declared_algo_400(s3_url):
    k = _key(s3_url)
    r = requests.put(
        k, data=DATA, headers={"x-amz-sdk-checksum-algorithm": "MD5"}, timeout=10
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Declaration-only (value carried elsewhere / computed by server)
# ---------------------------------------------------------------------------


def test_put_sdk_declaration_only_echoes(s3_url):
    k = _key(s3_url)
    r = requests.put(
        k, data=DATA, headers={"x-amz-sdk-checksum-algorithm": "SHA256"}, timeout=10
    )
    assert r.status_code == 200
    assert r.headers.get("x-amz-checksum-sha256") == CHECKSUMS["sha256"]
    requests.delete(k, timeout=10)


# ---------------------------------------------------------------------------
# GET/HEAD echo gated on x-amz-checksum-mode
# ---------------------------------------------------------------------------


def test_get_checksum_mode_enabled_echoes(s3_url):
    k = _key(s3_url)
    requests.put(k, data=DATA, headers={"x-amz-checksum-sha256": CHECKSUMS["sha256"]}, timeout=10)
    r = requests.get(k, headers={"x-amz-checksum-mode": "ENABLED"}, timeout=10)
    assert r.headers.get("x-amz-checksum-sha256") == CHECKSUMS["sha256"]
    # Without the opt-in header the additional algorithm is not echoed.
    r2 = requests.get(k, timeout=10)
    assert r2.headers.get("x-amz-checksum-sha256") is None
    requests.delete(k, timeout=10)


def test_default_put_still_echoes_crc64nvme(s3_url):
    # No checksum requested → historical crc64nvme default is computed + echoed.
    k = _key(s3_url)
    r = requests.put(k, data=DATA, timeout=10)
    assert r.status_code == 200
    assert r.headers.get("x-amz-checksum-crc64nvme") is not None
    requests.delete(k, timeout=10)
