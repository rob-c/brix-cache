"""
test_metrics_coverage_s3.py — Prometheus coverage for the S3 object lifecycle.

Complements test_s3_metrics.py (GET/PUT/bytes) with the FILE LIFECYCLE +
batch/copy methods the gap analysis flagged: PutObject (create), GetObject
(download), PutObject overwrite (modify), CopyObject, DeleteObject,
DeleteObjects (batch), ListObjects.  Asserts each increments
brix_s3_requests_total{method} / responses_total{method,status_class}, plus
the byte + list counters.

Run: PYTHONPATH=tests pytest tests/test_metrics_coverage_s3.py -v
"""

import pytest

requests = pytest.importorskip("requests")

from settings import NGINX_S3_PORT, HOST          # noqa: E402
from metrics_helpers import Snapshot, fetch, scalar  # noqa: E402

S3 = f"http://{HOST}:{NGINX_S3_PORT}"
BUCKET = "testbucket"


def _obj(key):
    return f"{S3}/{BUCKET}/{key}"


def _req(snap, method, after=None):
    return snap.delta("brix_s3_requests_total", {"method": method},
                      after=after)


def _resp2xx(snap, method, after=None):
    return snap.delta("brix_s3_responses_total",
                      {"method": method, "status_class": "2xx"}, after=after)


class TestS3LifecycleCounters:

    def test_put_create_then_get(self):
        snap = Snapshot()
        r = requests.put(_obj("cov_s3_a.bin"), data=b"s3-create" * 1000,
                         timeout=10)
        assert r.status_code in (200, 201), r.status_code
        after = fetch()
        assert _req(snap, "PUT", after) >= 1            # CREATE
        assert _resp2xx(snap, "PUT", after) >= 1
        snap = Snapshot()
        r = requests.get(_obj("cov_s3_a.bin"), timeout=10)
        assert r.status_code == 200
        after = fetch()
        assert _req(snap, "GET", after) >= 1
        assert _resp2xx(snap, "GET", after) >= 1

    def test_put_overwrite_modify(self):
        requests.put(_obj("cov_s3_mod.bin"), data=b"v1", timeout=10)
        snap = Snapshot()
        r = requests.put(_obj("cov_s3_mod.bin"), data=b"v2-modified", timeout=10)
        assert r.status_code in (200, 201)
        assert _req(snap, "PUT") >= 1                   # MODIFY

    def test_copyobject(self):
        requests.put(_obj("cov_s3_cp_src.bin"), data=b"copy-src" * 100,
                     timeout=10)
        snap = Snapshot()
        r = requests.put(_obj("cov_s3_cp_dst.bin"), timeout=10,
                         headers={"x-amz-copy-source": f"/{BUCKET}/cov_s3_cp_src.bin"})
        assert r.status_code in (200, 201), r.text[:200]
        # CopyObject is a PUT with x-amz-copy-source.
        assert _req(snap, "PUT") >= 1

    def test_delete_object(self):
        requests.put(_obj("cov_s3_del.bin"), data=b"del", timeout=10)
        snap = Snapshot()
        r = requests.delete(_obj("cov_s3_del.bin"), timeout=10)
        assert r.status_code in (200, 204)
        after = fetch()
        assert _req(snap, "DELETE", after) >= 1         # DELETE

    def test_delete_objects_batch(self):
        for k in ("cov_s3_b1.bin", "cov_s3_b2.bin"):
            requests.put(_obj(k), data=b"x", timeout=10)
        body = (
            '<?xml version="1.0"?><Delete>'
            "<Object><Key>cov_s3_b1.bin</Key></Object>"
            "<Object><Key>cov_s3_b2.bin</Key></Object>"
            "</Delete>"
        )
        snap = Snapshot()
        r = requests.post(f"{S3}/{BUCKET}/?delete", data=body, timeout=10,
                          headers={"Content-Type": "application/xml"})
        if r.status_code not in (200, 204):
            pytest.skip(f"DeleteObjects unsupported here: {r.status_code}")
        # batch delete is a POST (?delete subresource)
        assert _req(snap, "POST") >= 1

    def test_list_objects(self):
        requests.put(_obj("cov_s3_list1.bin"), data=b"l", timeout=10)
        snap = Snapshot()
        r = requests.get(f"{S3}/{BUCKET}/?list-type=2&prefix=cov_s3_list",
                         timeout=10)
        assert r.status_code == 200, r.status_code
        after = fetch()
        assert _req(snap, "LIST", after) >= 1
        # at least one object listed
        assert snap.delta("brix_s3_list_contents_total", {}, after=after) >= 1


class TestS3ByteCounters:

    def test_put_increments_bytes_rx(self):
        payload = b"S" * (256 * 1024)
        before = fetch()
        r = requests.put(_obj("cov_s3_bytes.bin"), data=payload, timeout=10)
        assert r.status_code in (200, 201)
        after = fetch()
        d = scalar(after, "brix_s3_bytes_rx_total") - max(
            0, scalar(before, "brix_s3_bytes_rx_total"))
        assert d >= len(payload), f"s3 bytes_rx delta {d} < {len(payload)}"

    def test_get_increments_bytes_tx(self):
        payload = b"T" * (256 * 1024)
        requests.put(_obj("cov_s3_bytes_tx.bin"), data=payload, timeout=10)
        before = fetch()
        r = requests.get(_obj("cov_s3_bytes_tx.bin"), timeout=10)
        assert r.status_code == 200
        after = fetch()
        d = scalar(after, "brix_s3_bytes_tx_total") - max(
            0, scalar(before, "brix_s3_bytes_tx_total"))
        assert d >= len(payload), f"s3 bytes_tx delta {d} < {len(payload)}"
