"""Manager LOGIN completion is explicit and occurs only after valid admission."""

import socket

import pytest

from _test_cms_wire_pup_conformance_helpers import (
    H, CMS_RR_LOGIN, NODE_DATA_PORT, _build_frame, _decode_login,
    _minimal_login_payload, _recv_frame, cms_server_ep, cms_server,
)
from _test_cms_hostile_conformance_helpers import CMS_RR_XAUTH

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-wire")]


def _assert_closed_without_ack(peer):
    """A reset or EOF is refusal; silence until the deadline is not evidence."""
    try:
        data = peer.recv(8)
    except ConnectionResetError:
        return
    assert data == b"", f"refused handshake unexpectedly received bytes: {data!r}"


def test_admitted_node_receives_complete_manager_login_ack(cms_server):
    """The first response is a complete LOGIN, not a later heartbeat or status."""
    with socket.create_connection((H, cms_server), timeout=8) as peer:
        peer.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                 _minimal_login_payload(NODE_DATA_PORT)))
        reply = _recv_frame(peer)
        assert reply is not None and reply[:3] == (0, CMS_RR_LOGIN, 0)
        fields = _decode_login(reply[3])
        assert fields["version"] == 3 and fields["mode"] == 0
        assert fields["sid"].startswith(b"brix-manager@")
        assert fields["sid"].endswith(f":{cms_server}".encode())
        assert fields["_tail_pos"] == len(reply[3])


def test_truncated_login_is_refused_without_ack(cms_server):
    """A truncated scalar cannot obtain a successful LOGIN acknowledgment."""
    with socket.create_connection((H, cms_server), timeout=8) as peer:
        peer.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\x80\x00"))
        _assert_closed_without_ack(peer)


def test_unsolicited_authentication_cannot_obtain_login_ack(cms_server):
    """An out-of-sequence auth frame must close rather than complete admission."""
    with socket.create_connection((H, cms_server), timeout=8) as peer:
        peer.sendall(_build_frame(0, CMS_RR_XAUTH, 0, b"\x00" * 8))
        _assert_closed_without_ack(peer)


@pytest.mark.parametrize("cms_server_ep", ["sss"], indirect=True)
def test_repeated_login_cannot_skip_an_outstanding_sss_challenge(cms_server_ep):
    """After a real SSS challenge, another LOGIN is not verified authentication."""
    with socket.create_connection((H, cms_server_ep.port), timeout=8) as peer:
        login = _build_frame(0, CMS_RR_LOGIN, 0, _minimal_login_payload(NODE_DATA_PORT))
        peer.sendall(login)
        challenge = _recv_frame(peer)
        assert challenge is not None and challenge[1] == CMS_RR_XAUTH
        assert b"&P=sss" in challenge[3]
        peer.sendall(login)
        _assert_closed_without_ack(peer)
