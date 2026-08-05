"""
tests/test_s3_xroot_mutations.py — S3 PUT/DELETE over a native root:// origin.

WHAT: the write half of the S3 x xroot cell — an S3 REST front whose
      brix_storage_backend is `root://`, driven with PUT, HEAD, DELETE and
      ListObjects, with the truth read off the ORIGIN's own export.

WHY:  the pairing existed in the matrix but was exercised with `requests.get`
      only, so the sd_xroot create-open / write / close and unlink slots reached
      from the S3 handler were configured and never driven — despite the cell's
      token being minted with `storage.modify:/`.
      docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 14.

HOW:  one nginx holds both ends (nginx_lc_s3_xroot.conf): the stream server on
      {PORT} owns {DATA_ROOT}, the S3 front on {S3_PORT} owns a SEPARATE and
      deliberately empty {EXPORT_ROOT}. Every assertion about where the bytes
      landed is a filesystem read of those two trees, never a GET back through
      the front — a read-through would pass whether or not the write left the
      front.

      Measured, not assumed (scratch probes, 2026-08-05):

          PUT /xrdbucket/<key>        200, empty body
          GET /xrdbucket/<key>        200, byte-exact
          HEAD /xrdbucket/<key>       200, Content-Length, no body
          GET /xrdbucket/             200, ListBucketResult XML
          DELETE /xrdbucket/<key>     204        (also 204 when absent)
          GET  after DELETE           404

Trio per CLAUDE.md:
  * success   — PUT lands byte-exact on the origin and nowhere else, survives a
                multi-chunk body, truncates on overwrite, and DELETE unlinks it.
  * error     — a missing key is 404 on GET, a DELETE of it is a no-op 204, and
                a PUT to an unconfigured bucket is NoSuchBucket with no write.
  * security  — traversal keys in four spellings write nothing outside the
                origin export, and the front's own export stays empty
                throughout: a write that never left the front would show there.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_s3_xroot_mutations.py -v
"""

import http.client
import pathlib

import pytest
import requests

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-s3-xroot")]

SPEC = "lc-s3-xroot"
BUCKET = "xrdbucket"

BODY = b"x" * 40000                     # several origin writes, one request
BIG = b"B" * (3 * 1024 * 1024)          # past client_body_buffer_size


class Front:
    """The S3 front, plus direct sight of both export trees."""

    def __init__(self, endpoint, export_root):
        self.base = f"http://{HOST}:{endpoint.extra_ports['S3_PORT']}"
        self.origin = pathlib.Path(endpoint.data_root)   # the root:// export
        self.front = export_root                         # the S3 front's own

    def url(self, key, bucket=BUCKET):
        return f"{self.base}/{bucket}/{key}"

    def put(self, key, data, bucket=BUCKET):
        return requests.put(self.url(key, bucket), data=data, timeout=120)

    def get(self, key, bucket=BUCKET):
        return requests.get(self.url(key, bucket), timeout=120)

    def delete(self, key, bucket=BUCKET):
        return requests.delete(self.url(key, bucket), timeout=120)

    def listing(self):
        r = requests.get(f"{self.base}/{BUCKET}/", timeout=60)
        assert r.status_code == 200, r.status_code
        return r.text

    def raw(self, method, path, body=b""):
        """A request whose path reaches the wire verbatim.

        `requests` collapses `..` segments client-side, so a traversal sent
        through it never leaves the machine — the server would be credited with
        a refusal it was never asked to make.
        """
        conn = http.client.HTTPConnection(HOST, int(self.base.rsplit(":", 1)[1]),
                                          timeout=60)
        try:
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def on_origin(self, rel):
        return self.origin / rel

    def front_files(self):
        return sorted(str(p.relative_to(self.front))
                      for p in self.front.rglob("*") if p.is_file())


@pytest.fixture(scope="module")
def front(tmp_path_factory):
    export_root = tmp_path_factory.mktemp("s3-xroot") / "export"
    export_root.mkdir(parents=True)

    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_lc_s3_xroot.conf",
            protocol="http",
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export_root)},
            reason="S3 PUT/DELETE over a native root:// origin"))
        yield Front(ep, export_root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# Success.                                                                     #
# --------------------------------------------------------------------------- #
def test_put_lands_on_the_origin_and_not_on_the_front(front):
    """The bytes must appear under the STREAM server's export, byte for byte."""
    assert front.put("landed.bin", BODY).status_code == 200
    assert front.on_origin("landed.bin").read_bytes() == BODY
    assert front.front_files() == [], "the write never left the S3 front"


def test_stored_object_round_trips_back_through_the_front(front):
    assert front.put("round.bin", BODY).status_code == 200
    r = front.get("round.bin")
    assert r.status_code == 200
    assert r.content == BODY
    assert int(r.headers["Content-Length"]) == len(BODY)


def test_head_reports_the_size_without_a_body(front):
    assert front.put("head.bin", BODY).status_code == 200
    r = requests.head(front.url("head.bin"), timeout=60)
    assert r.status_code == 200
    assert int(r.headers["Content-Length"]) == len(BODY)
    assert r.content == b""


def test_multi_chunk_put_round_trips(front):
    """3 MiB: the body outgrows one buffer, so the write loop actually loops."""
    assert front.put("big.bin", BIG).status_code == 200
    assert front.on_origin("big.bin").stat().st_size == len(BIG)
    assert front.get("big.bin").content == BIG


def test_overwriting_an_existing_object_truncates_it(front):
    assert front.put("over.bin", BIG).status_code == 200
    assert front.put("over.bin", b"S" * 10).status_code == 200
    assert front.on_origin("over.bin").read_bytes() == b"S" * 10


def test_delete_unlinks_the_object_on_the_origin(front):
    assert front.put("gone.bin", BODY).status_code == 200
    assert front.on_origin("gone.bin").exists()
    assert front.delete("gone.bin").status_code == 204
    assert not front.on_origin("gone.bin").exists()
    assert front.get("gone.bin").status_code == 404


def test_bucket_listing_follows_the_mutations(front):
    """ListObjects is served from the same origin namespace the writes hit."""
    assert front.put("listed.bin", BODY).status_code == 200
    assert "<Key>listed.bin</Key>" in front.listing()
    assert front.delete("listed.bin").status_code == 204
    assert "<Key>listed.bin</Key>" not in front.listing()


# --------------------------------------------------------------------------- #
# Error.                                                                       #
# --------------------------------------------------------------------------- #
def test_get_of_a_missing_key_is_404(front):
    assert front.get("never-written.bin").status_code == 404


def test_delete_of_a_missing_key_is_a_no_op(front):
    """S3 DELETE is idempotent: absent is success, not an error."""
    assert front.delete("never-written.bin").status_code == 204
    assert not front.on_origin("never-written.bin").exists()


def test_put_to_an_unconfigured_bucket_is_nosuchbucket(front):
    r = front.put("stray.bin", BODY, bucket="not-our-bucket")
    assert r.status_code == 404
    assert "<Code>NoSuchBucket</Code>" in r.text
    assert not front.on_origin("stray.bin").exists()
    assert front.front_files() == []


# --------------------------------------------------------------------------- #
# Security.                                                                    #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", [
    f"/{BUCKET}/../escape.bin",
    f"/{BUCKET}/a/../../escape.bin",
    f"/{BUCKET}/%2e%2e%2fescape.bin",
    f"/{BUCKET}/..%2Fescape.bin",
])
def test_traversal_keys_write_nothing_outside_the_export(front, path):
    """Each spelling normalises out of the bucket and is refused there."""
    status, body = front.raw("PUT", path, b"pwned")
    assert status == 404
    assert b"NoSuchBucket" in body
    assert not (front.origin.parent / "escape.bin").exists()
    assert not front.on_origin("escape.bin").exists()


def test_the_front_export_stays_empty_after_every_mutation(front):
    """The load-bearing invariant of this instance, asserted once at the end.

    The front and the origin are separate trees on purpose: if the S3 handler
    ever wrote through its own brix_export instead of the root:// backend, the
    round trips above would still pass and only this would fail.
    """
    assert front.put("final.bin", BODY).status_code == 200
    assert front.delete("final.bin").status_code == 204
    assert front.front_files() == []
