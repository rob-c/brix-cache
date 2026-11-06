"""Resource-complete authorization for S3 DeleteObjects.

DeleteObjects addresses its targets in the XML body, after the ordinary S3
request gate has seen only ``POST /bucket/?delete``.  These tests require every
resolved key to receive its own DELETE decision before the batch mutates any
object.  A mixed allowed/denied batch is deliberately atomic: authorization
failure leaves every object unchanged.
"""

import os
from xml.sax.saxutils import escape

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN


pytestmark = [
    pytest.mark.skipif(
        not os.path.exists(NGINX_BIN),
        reason="nginx binary (set NGINX_BIN) not available",
    ),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-s3-native-authz"),
]

_SERVER = "lc-s3-native-authz"
_BUCKET = "b"


def _body(*keys):
    objects = "".join(
        f"<Object><Key>{escape(key)}</Key></Object>" for key in keys
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<Delete>{objects}</Delete>"
    ).encode()


def _delete(endpoint, payload):
    return requests.post(
        f"{endpoint}/{_BUCKET}/?delete",
        data=payload,
        headers={"Content-Type": "application/xml"},
        timeout=15,
    )


@pytest.fixture()
def delete_authz_server(lifecycle, tmp_path):
    data = tmp_path / "data"
    for name in ("allowed", "blocked"):
        (data / name).mkdir(parents=True)

    authdb = tmp_path / "authdb"
    authdb.write_text(
        "u * /b/blocked -a /b/allowed d /b irw\n",
        encoding="utf-8",
    )
    endpoint = lifecycle.start(
        NginxInstanceSpec(
            name=_SERVER,
            template="nginx_lc_s3_delete_authz.conf",
            data_root=str(data),
            protocol="s3",
            template_values={
                "BIND_HOST": BIND_HOST,
                "AUTHDB": str(authdb),
            },
            reason="per-key S3 DeleteObjects authorization",
        )
    )
    yield f"http://{BIND_HOST}:{endpoint.port}", data


def test_fully_authorized_batch_deletes_every_key(delete_authz_server):
    endpoint, data = delete_authz_server
    keys = ("allowed/one.txt", "allowed/two.txt")
    for key in keys:
        (data / key).write_text(key, encoding="utf-8")

    response = _delete(endpoint, _body(*keys))

    assert response.status_code == 200, response.text
    assert all(not (data / key).exists() for key in keys)


def test_malformed_batch_does_not_delete_authorized_key(delete_authz_server):
    endpoint, data = delete_authz_server
    key = "allowed/survivor.txt"
    (data / key).write_text("survive", encoding="utf-8")
    payload = (
        f"<Delete><Object><Key>{key}</Key></Object>"
        "<Object></Object></Delete>"
    ).encode()

    response = _delete(endpoint, payload)

    assert response.status_code == 400
    assert "MalformedXML" in response.text
    assert (data / key).read_text(encoding="utf-8") == "survive"


def test_mixed_authorization_batch_is_atomic(delete_authz_server):
    endpoint, data = delete_authz_server
    allowed = "allowed/kept.txt"
    denied = "blocked/protected.txt"
    (data / allowed).write_text("allowed", encoding="utf-8")
    (data / denied).write_text("protected", encoding="utf-8")

    response = _delete(endpoint, _body(allowed, denied))

    assert response.status_code == 403
    assert "AccessDenied" in response.text
    assert (data / allowed).read_text(encoding="utf-8") == "allowed"
    assert (data / denied).read_text(encoding="utf-8") == "protected"


def test_object_key_delete_query_cannot_claim_batch_exemption(
    delete_authz_server,
):
    endpoint, data = delete_authz_server
    key = "blocked/object-route.txt"
    (data / key).write_text("protected", encoding="utf-8")

    response = requests.post(
        f"{endpoint}/{_BUCKET}/{key}?delete",
        data=b"",
        headers={"Content-Type": "application/xml"},
        timeout=15,
    )

    assert response.status_code == 403
    assert "AccessDenied" in response.text
    assert (data / key).read_text(encoding="utf-8") == "protected"
