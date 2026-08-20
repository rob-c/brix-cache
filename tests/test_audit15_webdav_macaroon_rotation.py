"""
test_audit15_webdav_macaroon_rotation.py — WebDAV twin of the root:// macaroon
key-rotation coverage in test_macaroon_root_wire.py (audit §A1,
testsuite-combinatorial-coverage-audit 2026-08-15: `brix_webdav_macaroon_secret_old`
had ZERO coverage; only the stream-plane rotation path was ever driven).

The C path under test (src/protocols/webdav/auth_token_verify.c): a macaroon
rejected by the CURRENT secret is retried once against the configured old
secret — the `nginx -s reload` grace window during key rotation — while any
OTHER secret still fails both checks.  The three cases:

  * current-secret macaroon  -> authenticates (rotation must not break new keys)
  * old-secret macaroon      -> authenticates (the grace retry)
  * third-secret macaroon    -> rejected (grace covers exactly ONE listed old
    key; anything else would be an HMAC bypass dressed up as rotation)
"""

import os
import sys

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from test_token_macaroon import make_macaroon       # noqa: E402

from settings import NGINX_BIN, HOST, BIND_HOST     # noqa: E402
from server_registry import NginxInstanceSpec        # noqa: E402

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15-mac-rotation")]

SECRET_HEX = "deadbeef" * 8
OLD_SECRET_HEX = "0badc0de" * 8
OTHER_SECRET_HEX = "cafebabe" * 8

SECRET = bytes.fromhex(SECRET_HEX)
OLD_SECRET = bytes.fromhex(OLD_SECRET_HEX)
OTHER_SECRET = bytes.fromhex(OTHER_SECRET_HEX)

CAVEATS = ["activity:DOWNLOAD", "path:/", "before:2099-12-31T23:59:59Z"]


@pytest.fixture()
def mac_port(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / "test.txt").write_text("hello-rotation\n")
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15-mac-rotation",
        template="nginx_lc_webdav_macaroon_rotation.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "CADIR": str(cadir), "SECRET_HEX": SECRET_HEX,
                         "OLD_SECRET_HEX": OLD_SECRET_HEX},
        reason="audit-15 webdav macaroon secret rotation grace"))
    return ep.port


def _get(port, secret):
    tok = make_macaroon(secret, "rotation-subject", CAVEATS,
                        location=f"http://{HOST}:{port}")
    return requests.get(f"http://{HOST}:{port}/test.txt",
                        headers={"Authorization": f"Bearer {tok}"}, timeout=10)


def test_current_secret_authenticates(mac_port):
    # Success/control: the live key keeps working with a grace key configured.
    assert _get(mac_port, SECRET).status_code in (200, 206), \
        "a macaroon signed with the CURRENT secret must authenticate"


def test_old_secret_accepted_during_grace(mac_port):
    # The rotation path itself: rejected by the current secret, accepted on
    # the single retry against brix_webdav_macaroon_secret_old.
    assert _get(mac_port, OLD_SECRET).status_code in (200, 206), \
        "a macaroon signed with the configured OLD secret must authenticate " \
        "during the rotation grace window"


def test_third_secret_still_rejected(mac_port):
    # Security-negative: grace covers exactly the one listed old key — any
    # other signing key must fail both HMAC checks.
    assert _get(mac_port, OTHER_SECRET).status_code not in (200, 206), \
        "a macaroon signed with an UNLISTED secret must NOT authenticate"
