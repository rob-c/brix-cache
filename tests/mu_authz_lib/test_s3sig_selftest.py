"""Self-test for the SigV4 signer (deterministic, no network)."""
import datetime

from mu_authz_lib import s3sig


def _fixed_now():
    return datetime.datetime(2026, 7, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)


def test_signature_is_deterministic_for_fixed_time():
    h1 = s3sig.signed_headers("GET", "/bucket/obj", "AKIATEST", "secret",
                              host="127.0.0.1:12105", now=_fixed_now())  # net-literal-allow: S3 SigV4 signed Host in golden-signature selftest
    h2 = s3sig.signed_headers("GET", "/bucket/obj", "AKIATEST", "secret",
                              host="127.0.0.1:12105", now=_fixed_now())  # net-literal-allow: S3 SigV4 signed Host in golden-signature selftest
    assert h1 == h2
    assert h1["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIATEST/20260706/")
    assert "SignedHeaders=host;x-amz-date" in h1["Authorization"]
    assert h1["x-amz-date"] == "20260706T120000Z"


def test_different_key_changes_signature():
    h1 = s3sig.signed_headers("GET", "/bucket/obj", "AKIA_ALICE", "s1",
                              host="h:1", now=_fixed_now())
    h2 = s3sig.signed_headers("GET", "/bucket/obj", "AKIA_BOB", "s2",
                              host="h:1", now=_fixed_now())
    assert h1["Authorization"] != h2["Authorization"]
