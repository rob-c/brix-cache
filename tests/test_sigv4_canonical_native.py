"""Check real query canonicalization with locally signed fixture URLs only."""

import datetime as dt
import hashlib
import hmac
from pathlib import Path
import subprocess
from urllib.parse import parse_qsl, urlencode, urlparse

import pytest

from settings import HOST
from test_platform_linux_native import native_compile
from test_s3_presigned import (
    SECRET_KEY, REGION, _canonical_query, _canonical_uri, _presigned_get_url,
    _signing_key, _string_to_sign,
)


@pytest.fixture(scope="module")
def canonical_binary(native_compile):
    source = (Path(__file__).parent / "c/sigv4_canonical_test.c").read_text()
    return native_compile(
        "sigv4-canonical", source,
        ["src/protocols/s3/auth_sigv4_canonical.c", "src/core/compat/uri.c",
         "src/core/compat/hex.c"],
        ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
    )


def _fixture_url(token=None):
    now = dt.datetime(2026, 9, 14, 4, 35, 13, tzinfo=dt.timezone.utc)
    return urlparse(_presigned_get_url(
        f"http://{HOST}:11944", "presigned/success.txt", request_time=now,
        session_token=token))


def _canonical(canonical_binary, query):
    result = subprocess.run([str(canonical_binary), "canonical", query],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _signature(parsed, canonical_query, params):
    request = (f"GET\n{_canonical_uri(parsed.path)}\n{canonical_query}\n"
               f"host:{parsed.netloc}\n\nhost\nUNSIGNED-PAYLOAD")
    date = params["X-Amz-Date"][:8]
    return hmac.new(_signing_key(SECRET_KEY, date, REGION),
                    _string_to_sign(params["X-Amz-Date"], date, request).encode(),
                    hashlib.sha256).hexdigest()


@pytest.mark.parametrize("token", [None, "static-session-token"], ids=["plain", "sts"])
def test_presigned_credential_survives_canonicalization(canonical_binary, token):
    parsed = _fixture_url(token)
    params = dict(parse_qsl(parsed.query))
    signature = params.pop("X-Amz-Signature")
    canonical = _canonical(canonical_binary, parsed.query)
    assert canonical == _canonical_query(params)
    assert len(params["X-Amz-Credential"]) > 32
    assert hmac.compare_digest(_signature(parsed, canonical, params), signature)


def test_modified_credential_does_not_keep_the_original_signature(canonical_binary):
    parsed = _fixture_url()
    params = dict(parse_qsl(parsed.query))
    signature = params["X-Amz-Signature"]
    params["X-Amz-Credential"] = params["X-Amz-Credential"].replace(
        "test-access-key/", "different-access-key/")
    query = urlencode(params)
    params.pop("X-Amz-Signature")
    canonical = _canonical(canonical_binary, query)
    assert canonical == _canonical_query(params)
    assert not hmac.compare_digest(_signature(parsed, canonical, params), signature)


def test_short_output_stays_terminated_inside_its_buffer(canonical_binary):
    result = subprocess.run([str(canonical_binary), "bounds", _fixture_url().query],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
