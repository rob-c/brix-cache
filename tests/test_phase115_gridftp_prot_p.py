"""Phase-115 W5.1 — the protected (PROT P) outbound GridFTP data channel.

A GridFTP control channel can be fully GSI-authenticated while its DATA channel
runs in the clear: that is exactly what PROT C is, and it is the historical
default.  PROT P closes the gap by putting TLS on the data socket presenting the
SAME X.509 proxy the control channel authenticated with, and pinning the data
peer's leaf DN to the control channel's identity — so a third party that can
reach the passive data port cannot read the bytes, and cannot answer for the
origin either.

Two properties are worth testing and only one of them is "it works":

1. `prot=p` moves the bytes correctly (a protected channel that corrupts data is
   not protection, it is an outage).
2. `prot=p` FAILS CLOSED.  The failure mode that matters is not an error — it is
   an origin that cannot protect the data channel, and a driver that shrugs and
   sends the bytes in the clear anyway.  The operator wrote one word on a store
   line and would have no way to discover it was ignored.

The lab makes (2) provable rather than merely asserted: the unsecured origin
that refuses the protected front is reached by a FOURTH front over plain
``ftp://``, which serves the same file happily.  Without that differential a
green refusal test could just as well be describing a broken origin.

PROT P has no meaning without a GSI control channel to pin against — the driver
refuses `prot=p` on an `ftp://` store at CONFIG time for that reason, which is
pinned in test_phase115_gridftp_data_channel_parse.py rather than here.
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import time

import pytest

from pki_helpers import blitz_test_pki
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (
    BIND_HOST, CA_DIR, NGINX_BIN, PROXY_STD, SERVER_CERT, SERVER_HOST,
    SERVER_KEY,
)


pytestmark = [
    pytest.mark.serial,
    pytest.mark.slow,
    pytest.mark.timeout(300),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-prot-p"),
]

PAYLOAD = b"protected-data-channel-payload\n" * 4096


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        try:
            body = response.read()
        except http.client.IncompleteRead as partial:
            body = partial.partial
        return response.status, body
    finally:
        connection.close()


def _put(port: int, path: str, body: bytes) -> int:
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request("PUT", path, body=body)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def _await_log(path: Path, needle: str, timeout: float = 25.0) -> str:
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if needle in line:
                return line
        time.sleep(0.2)
    raise AssertionError(f"{needle!r} never reached {path}\n--- tail ---\n"
                         + "\n".join(text.splitlines()[-40:]))


class _ProtLab:
    def __init__(self, harness: LifecycleHarness, tmp: Path):
        root = tmp / "origin"
        root.mkdir()
        (root / "payload.bin").write_bytes(PAYLOAD)
        exports = {}
        for key in ("P_EXPORT", "C_EXPORT", "REFUSE_EXPORT", "PLAIN_EXPORT"):
            path = tmp / key.lower()
            path.mkdir()
            exports[key] = str(path)
        origin = harness.start(NginxInstanceSpec(
            name="lc-p115-prot-p-origin",
            template="nginx_lc_gsiftp_prot_p_origin.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_ROOT": str(root),
                "CA_DIR": CA_DIR,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
            },
            reason="the GSI and unsecured GridFTP origins, in their own worker",
        ))
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-p115-prot-p",
            template="nginx_lc_gsiftp_prot_p.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "GSI_ORIGIN_PORT": origin.port,
                "PLAIN_ORIGIN_PORT": origin.extra_ports["PLAIN_ORIGIN_PORT"],
                "USER_PROXY": PROXY_STD,
                "CA_DIR": CA_DIR,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                **exports,
            },
            reason="protected and cleartext GridFTP data channels side by side",
        ))
        self.harness = harness
        self.root = root
        self.port = endpoint.port
        self.clear_port = endpoint.extra_ports["CLEAR_PORT"]
        self.refuse_port = endpoint.extra_ports["REFUSE_PORT"]
        self.plain_ok_port = endpoint.extra_ports["PLAIN_OK_PORT"]
        self.error_log = Path(endpoint.prefix, "logs", "error.log")

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    blitz_test_pki()
    if not Path(PROXY_STD).is_file():
        pytest.skip("standard X.509 proxy unavailable")
    harness = LifecycleHarness()
    lab = _ProtLab(harness, tmp_path_factory.mktemp("p115-prot-p"))
    yield lab
    lab.close()


# ---- success -----------------------------------------------------------------

def test_protected_data_channel_delivers_the_bytes(lab):
    assert _get(lab.port, "/payload.bin") == (200, PAYLOAD)


def test_protected_and_cleartext_channels_agree_byte_for_byte(lab):
    """The protection is invisible above the driver, which is the contract."""
    protected = _get(lab.port, "/payload.bin")[1]
    cleartext = _get(lab.clear_port, "/payload.bin")[1]
    assert protected == cleartext == PAYLOAD


def test_protected_put_lands_on_the_origin(lab):
    """The send half: TLS is negotiated per data connection, in both directions."""
    assert _put(lab.port, "/uploaded.bin", PAYLOAD) in (201, 204)
    assert (lab.root / "uploaded.bin").read_bytes() == PAYLOAD


def test_the_store_line_is_what_selected_the_protection(lab):
    """`prot=p` on the store line, not a default, is what turned TLS on.

    The builder announces the negotiated policy per export at startup, so the
    two fronts must announce DIFFERENT ones — otherwise the success above would
    be equally green with the parameter deleted.
    """
    _await_log(lab.error_log, "prot=P")
    _await_log(lab.error_log, "prot=C")


# ---- fail closed --------------------------------------------------------------

def test_unprotectable_origin_is_refused_rather_than_served_in_the_clear(lab):
    """The security property of the whole feature.

    The origin has no security layer at all, so it cannot protect a data
    channel.  The one outcome that must never happen is the bytes arriving
    anyway: an operator who wrote `prot=p` would then be running a plaintext
    data channel and reading a 200.
    """
    status, body = _get(lab.refuse_port, "/payload.bin")
    assert status >= 400, f"served {status} over an unprotectable data channel"
    assert PAYLOAD[:64] not in body


def test_the_refused_origin_is_otherwise_perfectly_healthy(lab):
    """The differential that makes the refusal above mean something.

    Same origin, same file, same front process — the one difference is a store
    line without `prot=p`.  If this failed too, the refusal test would be
    describing a broken lab.
    """
    assert _get(lab.plain_ok_port, "/payload.bin") == (200, PAYLOAD)


def test_a_refused_protected_channel_leaves_no_write_path_open(lab):
    """A failure on the read path must not leave the export writable either.

    The protected front onto the unsecured origin is `brix_allow_write off`, so
    this is also the typed VFS read-only gate answering before any backend
    dial — belt and braces, and cheap to state.
    """
    assert _put(lab.refuse_port, "/smuggled.bin", b"x") >= 400
    assert not (lab.root / "smuggled.bin").exists()
