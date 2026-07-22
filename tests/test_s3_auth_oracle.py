"""
tests/test_s3_auth_oracle.py

Coverage gap #1 (test-coverage-gap-audit): S3 SigV4 must not be an
access-key-enumeration oracle.

An UNKNOWN access key and a KNOWN key with a BAD signature must be
INDISTINGUISHABLE: both → 403 with <Code>SignatureDoesNotMatch</Code>, and the
response must never reveal InvalidAccessKeyId / NoSuchKey (which would let an
attacker enumerate valid access keys).  Existing tests either probe a bad key
while accepting "any" status (test_s3_metrics) or use the CORRECT key for the
bad-signature case (test_s3_presigned) — neither can detect an oracle.

Self-contained: spawns a SigV4-enforcing S3 server (access/secret configured).
"""

import datetime as dt
import hashlib
import hmac
import os
import re
from urllib.parse import quote

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-s3-auth-oracle")]

PORT = None
BUCKET = "testbucket"
REGION = "us-east-1"
ACCESS_KEY = "test-access-key"
SECRET_KEY = "test-secret-key"
KEYOBJ = "obj.txt"


@pytest.fixture()
def s3_server(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    data = tmp_path / "data"
    data.mkdir()
    (data / KEYOBJ).write_text("s3-oracle-object\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-s3-auth-oracle",
        template="nginx_lc_s3_auth_oracle.conf",
        protocol="s3",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "BUCKET": BUCKET, "ACCESS_KEY": ACCESS_KEY,
                         "SECRET_KEY": SECRET_KEY, "REGION": REGION},
        reason="s3 SigV4 auth oracle"))
    global PORT
    PORT = ep.port
    yield


def _signing_key(secret, date):
    k = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def _signed_headers(access_key, secret_key, *, corrupt_sig=False):
    """Build a SigV4 header-auth GET for /BUCKET/KEYOBJ with the given key+secret
    (mirrors the server's canonicalization: SignedHeaders=host;x-amz-date)."""
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    host = f"{HOST}:{PORT}"
    path = f"/{BUCKET}/{KEYOBJ}"
    canonical = (
        "GET\n"
        f"{quote(path, safe='/-_.~')}\n"
        "\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        "\n"
        "host;x-amz-date\n"
        "UNSIGNED-PAYLOAD"
    )
    sts = ("AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{date}/{REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    sig = hmac.new(_signing_key(secret_key, date), sts.encode(),
                   hashlib.sha256).hexdigest()
    if corrupt_sig:
        sig = ("0" * 8) + sig[8:]
    cred = f"{access_key}/{date}/{REGION}/s3/aws4_request"
    return {
        "x-amz-date": amz_date,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={cred}, "
                          f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }


def _get(headers):
    return requests.get(f"http://{HOST}:{PORT}/{BUCKET}/{KEYOBJ}",
                        headers=headers, timeout=10)


def _err_code(body_bytes):
    m = re.search(rb"<Code>([^<]+)</Code>", body_bytes)
    return m.group(1).decode() if m else None


def test_positive_control_valid_signature_accepted(s3_server):
    r = _get(_signed_headers(ACCESS_KEY, SECRET_KEY))
    assert r.status_code == 200, \
        f"correctly-signed request must succeed (got {r.status_code}); oracle broken"


def test_unknown_key_and_bad_sig_are_indistinguishable(s3_server):
    # Unknown access key (server has no secret for it).
    unknown = _get(_signed_headers("AKIA-DOES-NOT-EXIST", "irrelevant-secret"))
    # Known key, wrong secret → signature mismatch.
    badsig = _get(_signed_headers(ACCESS_KEY, "the-wrong-secret"))

    for label, resp in (("unknown-key", unknown), ("bad-sig", badsig)):
        assert resp.status_code == 403, \
            f"{label}: expected 403, got {resp.status_code}"
        code = _err_code(resp.content)
        assert code == "SignatureDoesNotMatch", \
            f"{label}: expected SignatureDoesNotMatch, got {code!r} ({resp.content[:200]!r})"
        # Must NOT leak that the access key is unknown / object exists.
        assert b"InvalidAccessKeyId" not in resp.content, f"{label} leaked InvalidAccessKeyId"
        assert b"NoSuchKey" not in resp.content, f"{label} leaked NoSuchKey"

    # The two cases must be byte-identical in status + error code (no oracle).
    assert unknown.status_code == badsig.status_code, "status oracle between unknown-key and bad-sig"
    assert _err_code(unknown.content) == _err_code(badsig.content), \
        "error-code oracle between unknown-key and bad-sig"


def test_missing_auth_rejected(s3_server):
    # No Authorization at all → must be rejected (not anonymous-served).
    r = requests.get(f"http://{HOST}:{PORT}/{BUCKET}/{KEYOBJ}", timeout=10)
    assert r.status_code in (400, 403), \
        f"unauthenticated request to a SigV4 endpoint must be rejected, got {r.status_code}"
