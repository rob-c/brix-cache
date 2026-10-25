"""Focused contract tests for the persistent CMS parent fleet stub."""

import socket
import threading

import cms_parent_stubs as stub


def _frame(code, streamid=0, payload=b""):
    return stub.struct.pack(">IBBH", streamid, code, 0, len(payload)) + payload


def _serve(server, response=lambda: (stub.CMS_RR_SELECT, b"target")):
    def _run():
        try:
            stub._handle_connection(server, response, 0.05)
        except (ConnectionError, OSError):
            pass
        finally:
            server.close()

    thread = threading.Thread(
        target=_run,
        daemon=True,
    )
    thread.start()
    return thread


def _close(client, server, thread):
    client.close()
    server.close()
    thread.join(timeout=1)


def test_parent_stub_sends_manager_heartbeat_while_node_is_idle():
    """Success: an idle registered node receives manager-originated PING."""
    server, client = socket.socketpair()
    thread = _serve(server)
    try:
        client.sendall(_frame(stub.CMS_RR_LOGIN))
        streamid, opcode, payload = stub._recv_frame(client)
        assert (streamid, opcode, payload) == (0, stub.CMS_RR_PING, b"")
    finally:
        _close(client, server, thread)


def test_parent_stub_still_answers_locate_after_heartbeat():
    """Success: heartbeat traffic does not consume or corrupt a LOCATE reply."""
    server, client = socket.socketpair()
    thread = _serve(server, lambda: (stub.CMS_RR_SELECT, b"leaf"))
    try:
        client.sendall(_frame(stub.CMS_RR_LOGIN))
        assert stub._recv_frame(client)[1] == stub.CMS_RR_PING
        client.sendall(_frame(stub.CMS_RR_LOCATE, streamid=73, payload=b"/x"))
        assert stub._recv_frame(client) == (73, stub.CMS_RR_SELECT, b"leaf")
    finally:
        _close(client, server, thread)


def test_parent_stub_rejects_non_login_before_sending_heartbeat():
    """Security-negative: an unregistered peer receives no manager traffic."""
    server, client = socket.socketpair()
    client.settimeout(0.2)
    thread = _serve(server)
    try:
        client.sendall(_frame(stub.CMS_RR_LOCATE, streamid=91, payload=b"/x"))
        assert client.recv(1) == b""
    finally:
        _close(client, server, thread)
