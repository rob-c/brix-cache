"""Live HTTP parity tests for ``brix_token_jwks_refresh_interval``.

WebDAV and S3 retain separate validator-owned key arrays, while http_common
owns their worker timer lifecycle.  Each test starts one isolated worker with
both fronts and mutates one JWKS file atomically.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from tokenforge import TokenForge


pytestmark = [
    pytest.mark.timeout(90),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-http-jwks-refresh"),
]

BODY = "phase-105 HTTP JWKS refresh\n"


def _replace_jwks(path: str, content: str) -> None:
    target = Path(path)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_text(content)
    os.replace(temporary, target)
    stamp = time.time() + 2
    os.utime(target, (stamp, stamp))


def _status(port: int, token: str, *, s3: bool = False) -> int:
    path = "/testbucket/test.txt" if s3 else "/test.txt"
    response = requests.get(
        f"http://{HOST}:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    return response.status_code


def _both_statuses(node, token: str) -> tuple[int, int]:
    return (
        _status(node.port, token),
        _status(node.extra_ports["S3_PORT"], token, s3=True),
    )


def _wait_for_statuses(node, token: str, expected: set[int], timeout=5.0):
    deadline = time.monotonic() + timeout
    last = (0, 0)
    while time.monotonic() < deadline:
        last = _both_statuses(node, token)
        if all(status in expected for status in last):
            return last
        time.sleep(0.05)
    return last


@pytest.fixture()
def http_jwks(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    original = TokenForge(str(tmp_path / "original"))
    original.init_keys()
    data = tmp_path / "data"
    for plane in ("dav", "s3"):
        root = data / plane
        root.mkdir(parents=True)
        (root / "test.txt").write_text(BODY)
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-http-jwks-refresh",
        template="nginx_lc_http_jwks_refresh.conf",
        protocol="webdav",
        readiness="tcp",
        data_root=str(data),
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "CADIR": str(cadir),
            "JWKS": original.jwks_path,
            "ISSUER": original.issuer,
            "AUDIENCE": original.audience,
        },
        reason="phase-105 W4.3 HTTP JWKS refresh parity",
    ))
    return endpoint, original


def test_initial_jwks_authenticates_on_webdav_and_s3(http_jwks):
    """Success: both HTTP validators use their initially loaded key set."""
    node, issuer = http_jwks
    token = issuer.generate(scope="storage.read:/")
    assert _both_statuses(node, token) == (200, 200)


def test_invalid_refresh_preserves_both_http_key_sets(http_jwks):
    """Error: a malformed replacement cannot discard the last good keys."""
    node, issuer = http_jwks
    token = issuer.generate(scope="storage.read:/")
    _replace_jwks(issuer.jwks_path, '{"keys":[{"kty":"BROKEN"}]}')
    assert _wait_for_statuses(node, token, {200}) == (200, 200)


def test_removed_key_is_rejected_on_webdav_and_s3(http_jwks, tmp_path):
    """Security-negative: rotation accepts the new key and revokes the old."""
    node, original = http_jwks
    old_token = original.generate(scope="storage.read:/")
    rotated = TokenForge(str(tmp_path / "rotated"))
    rotated.init_keys()
    _replace_jwks(original.jwks_path, Path(rotated.jwks_path).read_text())

    new_token = rotated.generate(scope="storage.read:/")
    assert _wait_for_statuses(node, new_token, {200}) == (200, 200)
    refused = _wait_for_statuses(node, old_token, {401, 403})
    assert all(status in (401, 403) for status in refused), refused
