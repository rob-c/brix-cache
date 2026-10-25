"""HEAD must never put XML error bodies on a reusable HTTP connection."""

import socket
import pytest
import requests

from settings import HOST
from mu_authz_lib.s3sig import signed_headers
import test_s3_auth_oracle as oracle
from test_s3_auth_oracle import s3_server  # noqa: F401 — real SigV4 fixture
from test_s3_keepalive_after_write import _request, _recv_head, _send

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-s3-auth-oracle")]


def _headers(method, path, secret=oracle.SECRET_KEY):
    return signed_headers(method, path, oracle.ACCESS_KEY, secret, host="s3.test")


@pytest.mark.parametrize("scenario,status,suffix,secret", [
    ("existing", 200, "", oracle.SECRET_KEY),
    ("missing", 404, ".absent", oracle.SECRET_KEY),
    ("denied", 403, "", "wrong-secret"),
])
def test_head_cannot_desynchronize_the_next_response(s3_server, scenario, status, suffix, secret):
    """Successful, missing and denied HEADs leave the next status line intact."""
    path = f"/{oracle.BUCKET}/{oracle.KEYOBJ}"
    head_path = path + suffix
    with socket.create_connection((HOST, oracle.PORT), timeout=10) as sock:
        _send(sock, "HEAD", head_path, b"", _headers("HEAD", head_path, secret))
        head_status, _headers_out, forbidden_body = _recv_head(sock)
        assert head_status == status
        assert forbidden_body == b"", "HEAD emitted a forbidden response body"
        # A delayed HEAD body also fails here, before the next HTTP status line.
        get_status, _headers_out, body = _request(
            sock, "GET", path, headers=_headers("GET", path))
        assert get_status == 200 and body == b"s3-oracle-object\n"
    if scenario == "missing":
        error = requests.get(f"http://{HOST}:{oracle.PORT}" + head_path,
                             headers={"Host": "s3.test", **_headers("GET", head_path)},
                             timeout=10)
        assert error.status_code == 404 and "<Error>" in error.text
