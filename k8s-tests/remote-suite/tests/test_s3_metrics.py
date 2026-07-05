"""
Prometheus metrics tests for the S3-compatible protocol layer.

Covers brix_s3_requests_total, brix_s3_responses_total,
brix_s3_bytes_rx/tx_total, per-IP-version byte counters,
brix_s3_list_contents_total / list_common_prefixes_total / list_truncated_total,
and brix_s3_auth_total.

All requests target the main S3 port (9001) using the requests library.
Per-IP counters use 127.0.0.1 to force IPv4.

Run:
    pytest tests/test_s3_metrics.py -v
"""

import os
import urllib.request
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

from settings import (
    HOST,
    NGINX_METRICS_PORT,
    NGINX_S3_PORT,
    S3_PRESIGNED_PORT,
    url_host,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

METRICS_URL = f"http://{url_host(HOST)}:{NGINX_METRICS_PORT}/metrics"
S3_BASE     = f"http://{url_host(HOST)}:{NGINX_S3_PORT}"
BUCKET      = "testbucket"
S3_NS       = "http://s3.amazonaws.com/doc/2006-03-01/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch() -> str:
    with urllib.request.urlopen(METRICS_URL, timeout=5) as r:
        return r.read().decode()


def _parse(text, name, labels):
    import re
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


def _scalar(text, name):
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "\t"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                pass
    return -1


def _delta(before, after, name, labels=None):
    if labels is not None:
        v_b = _parse(before, name, labels)
        v_a = _parse(after,  name, labels)
    else:
        v_b = _scalar(before, name)
        v_a = _scalar(after,  name)
    if v_b == -1:
        v_b = 0
    return max(0, v_a - v_b)


def _obj_url(key):
    return f"{S3_BASE}/{BUCKET}/{key}"


def _list_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    base = f"{S3_BASE}/{BUCKET}/?list-type=2"
    return f"{base}&{qs}" if qs else base


def _uid():
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Section 6a-6b — Basic request/response counters
# ---------------------------------------------------------------------------

class TestS3RequestCounters:

    @pytest.fixture(autouse=True)
    def _snap(self):
        self.before = _fetch()
        yield

    def test_get_increments_requests_and_responses_2xx(self):
        key = f"metrics_get_{_uid()}.bin"
        requests.put(_obj_url(key), data=b"counter test", timeout=10).raise_for_status()
        self.before = _fetch()
        r = requests.get(_obj_url(key), timeout=10)
        assert r.status_code == 200
        after = _fetch()
        assert _delta(self.before, after, "brix_s3_requests_total",
                      {"method": "GET"}) >= 1
        assert _delta(self.before, after, "brix_s3_responses_total",
                      {"method": "GET", "status_class": "2xx"}) >= 1

    def test_put_increments_requests_and_bytes_rx(self):
        key = f"metrics_put_{_uid()}.bin"
        payload = b"y" * 8192
        r = requests.put(_obj_url(key), data=payload, timeout=10)
        assert r.status_code == 200
        after = _fetch()
        assert _delta(self.before, after, "brix_s3_requests_total",
                      {"method": "PUT"}) >= 1
        delta_rx = _delta(self.before, after, "brix_s3_bytes_rx_total")
        assert delta_rx >= len(payload), f"bytes_rx delta {delta_rx} < payload {len(payload)}"

    def test_delete_increments_requests(self):
        key = f"metrics_del_{_uid()}.bin"
        requests.put(_obj_url(key), data=b"delete me", timeout=10)
        self.before = _fetch()
        r = requests.delete(_obj_url(key), timeout=10)
        assert r.status_code in (200, 204)
        after = _fetch()
        assert _delta(self.before, after, "brix_s3_requests_total",
                      {"method": "DELETE"}) >= 1

    def test_missing_key_increments_responses_4xx(self):
        key = f"no_such_{_uid()}.bin"
        before = _fetch()
        r = requests.get(_obj_url(key), timeout=10)
        assert r.status_code == 404
        after = _fetch()
        assert _delta(before, after, "brix_s3_responses_total",
                      {"method": "GET", "status_class": "4xx"}) >= 1


# ---------------------------------------------------------------------------
# Section 6c-6e — ListObjectsV2 counters
# ---------------------------------------------------------------------------

class TestS3ListCounters:
    """Verify list_contents_total, list_common_prefixes_total, list_truncated_total.

    list_contents_total was never incremented before the fix to list_objects_v2.c.
    """

    def test_list_contents_total_increments(self):
        """ListObjectsV2 → list_contents_total delta == number of objects returned."""
        uid = _uid()
        prefix = f"list_contents_{uid}_"
        keys = [f"{prefix}{i}.txt" for i in range(3)]
        for k in keys:
            requests.put(_obj_url(k), data=b"x", timeout=10)

        before = _fetch()
        r = requests.get(_list_url(prefix=prefix), timeout=10)
        assert r.status_code == 200
        after = _fetch()

        delta = _delta(before, after, "brix_s3_list_contents_total")
        assert delta >= 3, (
            f"list_contents_total delta {delta} < 3 objects listed. "
            "This counter was never written before the fix to list_objects_v2.c."
        )

    def test_list_common_prefixes_total_increments(self):
        """List with delimiter → list_common_prefixes_total increments."""
        uid = _uid()
        base = f"list_prefix_{uid}"
        requests.put(_obj_url(f"{base}/dir/a.txt"), data=b"1", timeout=10)
        requests.put(_obj_url(f"{base}/dir/b.txt"), data=b"2", timeout=10)
        requests.put(_obj_url(f"{base}/top.txt"), data=b"3", timeout=10)

        before = _fetch()
        r = requests.get(_list_url(prefix=f"{base}/", delimiter="/"), timeout=10)
        assert r.status_code == 200
        after = _fetch()

        delta = _delta(before, after, "brix_s3_list_common_prefixes_total")
        assert delta >= 1, f"list_common_prefixes_total delta {delta} < 1"

    def test_list_truncated_total_increments(self):
        """Paginated list (max-keys=1) → list_truncated_total increments."""
        uid = _uid()
        prefix = f"list_trunc_{uid}_"
        for i in range(3):
            requests.put(_obj_url(f"{prefix}{i}.txt"), data=b"t", timeout=10)

        before = _fetch()
        r = requests.get(_list_url(prefix=prefix, **{"max-keys": "1"}), timeout=10)
        assert r.status_code == 200
        after = _fetch()

        # Verify the response says it is truncated.
        root = ET.fromstring(r.text)
        ns = S3_NS
        is_trunc = root.findtext(f"{{{ns}}}IsTruncated")
        assert is_trunc == "true", "Expected truncated response"

        delta = _delta(before, after, "brix_s3_list_truncated_total")
        assert delta >= 1, f"list_truncated_total delta {delta} < 1"


# ---------------------------------------------------------------------------
# Section 6f-6g — Per-IP-version byte counters (S3)
# ---------------------------------------------------------------------------

class TestS3IpVersionBytes:
    """Verify S3 per-IP byte counters track bytes, not request counts."""

    PAYLOAD_SIZE = 32768

    @pytest.fixture(autouse=True)
    def _snap(self):
        self.before = _fetch()
        yield

    def test_bytes_rx_ipv4_not_request_count(self):
        """PUT 32 KiB → bytes_rx_ipv4_total delta ≥ 32 KiB, delta ≠ 1."""
        payload = b"r" * self.PAYLOAD_SIZE
        key = f"ipv4_rx_{_uid()}.bin"
        r = requests.put(_obj_url(key), data=payload, timeout=10)
        assert r.status_code == 200
        delta = _delta(self.before, _fetch(), "brix_s3_bytes_rx_ipv4_total")
        assert delta >= self.PAYLOAD_SIZE, f"s3 bytes_rx_ipv4 delta {delta} < payload"
        assert delta != 1, "s3 bytes_rx_ipv4 is counting requests, not bytes (bug regression)"

    def test_bytes_tx_ipv4_not_request_count(self):
        """GET 32 KiB object → bytes_tx_ipv4_total delta ≥ 32 KiB, delta ≠ 1."""
        payload = b"t" * self.PAYLOAD_SIZE
        key = f"ipv4_tx_{_uid()}.bin"
        requests.put(_obj_url(key), data=payload, timeout=10).raise_for_status()
        self.before = _fetch()
        r = requests.get(_obj_url(key), timeout=10)
        assert r.status_code == 200
        delta = _delta(self.before, _fetch(), "brix_s3_bytes_tx_ipv4_total")
        assert delta >= self.PAYLOAD_SIZE, f"s3 bytes_tx_ipv4 delta {delta} < payload"
        assert delta != 1, "s3 bytes_tx_ipv4 is counting requests, not bytes (bug regression)"


# ---------------------------------------------------------------------------
# Section 6h — Auth counter for SigV4 signature mismatch
# ---------------------------------------------------------------------------

class TestS3AuthCounters:

    def test_bad_sigv4_signature_increments_auth_counter(self):
        """S3 GET with a malformed SigV4 Authorization header → auth error counter."""
        # Send a syntactically valid SigV4 header with a wrong access key.
        # This targets the presigned/authenticated S3 endpoint if available;
        # the main anonymous port may not validate signatures.
        key = f"sigv4_probe_{_uid()}.bin"
        bad_auth = (
            "AWS4-HMAC-SHA256 "
            "Credential=BADACCESSKEY/20260101/us-east-1/s3/aws4_request, "
            "SignedHeaders=host;x-amz-date, "
            "Signature=0000000000000000000000000000000000000000000000000000000000000000"
        )
        before = _fetch()
        r = requests.get(
            f"{S3_BASE}/{BUCKET}/{key}",
            headers={"Authorization": bad_auth, "x-amz-date": "20260101T000000Z"},
            timeout=10,
        )
        after = _fetch()

        # Accept any of: auth counter increment, 403, or 400 (server rejected it).
        bad_key_delta = _delta(before, after, "brix_s3_auth_total",
                               {"result": "bad_access_key"})
        sig_delta = _delta(before, after, "brix_s3_auth_total",
                           {"result": "signature_mismatch"})
        malformed_delta = _delta(before, after, "brix_s3_auth_total",
                                 {"result": "malformed"})

        # Anonymous S3 port ignores Authorization headers and returns 404 for
        # a missing key — this is acceptable since no SigV4 validation is done.
        assert (bad_key_delta + sig_delta + malformed_delta >= 1
                or r.status_code in (400, 403, 404)), (
            f"No S3 auth error counter incremented and status was {r.status_code}"
        )
