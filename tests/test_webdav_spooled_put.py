"""
Regression test for WebDAV PUT bodies that nginx spools to a temp file.

The WebDAV handler receives large HTTPS request bodies after nginx has already
written them to client_body_temp_path. This test forces that path with
client_body_in_file_only so uploads exercise the module's temp-file copy path
instead of the small in-memory buffer case.
"""

import os
import sys

import pytest
import requests
import urllib3
from settings import DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD, TOKENS_DIR

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY_PEM = PROXY_STD

WEBDAV_URL = ""
DATA_DIR   = DEFAULT_DATA_ROOT
TOKEN_DIR  = TOKENS_DIR
AUTH_MODE  = "gsi"
TOKEN      = ""


@pytest.fixture(scope="module", autouse=True, params=("gsi", "token"),
                ids=("gsi-8444", "token-8443"))
def _configure(request, test_env):
    """Bind module constants from the shared test environment."""
    global WEBDAV_URL, DATA_DIR, PROXY_PEM, TOKEN_DIR, AUTH_MODE, TOKEN
    AUTH_MODE  = request.param
    WEBDAV_URL = (
        test_env["webdav_gsi_tls_url"]
        if AUTH_MODE == "gsi"
        else test_env["webdav_url"]
    )
    DATA_DIR   = test_env["data_dir"]
    PROXY_PEM  = test_env["proxy_pem"]
    TOKEN_DIR  = test_env.get("token_dir", TOKENS_DIR)
    TOKEN      = ""

    if AUTH_MODE == "token":
        issuer = TokenIssuer(TOKEN_DIR)
        if not os.path.exists(issuer.key_path):
            issuer.init_keys()
        TOKEN = issuer.generate(
            scope="storage.read:/ storage.write:/",
            lifetime=7200,
        )


def _auth_kwargs():
    if AUTH_MODE == "gsi":
        return {"cert": PROXY_PEM}
    return {"headers": {"Authorization": f"Bearer {TOKEN}"}}


def test_put_spooled_request_body_round_trips():
    name = f"spooled-upload-{AUTH_MODE}.bin"
    payload = os.urandom((2 * 1024 * 1024) + 137)

    resp = requests.put(
        f"{WEBDAV_URL}/{name}",
        data=payload,
        verify=False,
        timeout=30,
        **_auth_kwargs(),
    )

    assert resp.status_code in (201, 204), resp.text

    with open(os.path.join(DATA_DIR, name), "rb") as fh:
        assert fh.read() == payload
