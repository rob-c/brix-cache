"""Fault injection follows request opcodes, never opaque client stream IDs."""
import io
import struct
import threading

from test_tpc_pull_integrity import _KxrPullFaultProxy


class MemorySocket:
    def __init__(self, data=b""):
        self.input = io.BytesIO(data)
        self.output = bytearray()

    def recv(self, size):
        return self.input.read(min(size, 3))

    def sendall(self, data):
        self.output.extend(data)

    def shutdown(self, direction):
        pass


def _exchange(opcode, sid):
    proxy = _KxrPullFaultProxy("unused", 1)
    request = sid + struct.pack("!H", opcode) + bytes(20)
    requests = {}
    lock = threading.Lock()
    upstream = MemorySocket()
    proxy._pump_up(MemorySocket(bytes(20) + request), upstream, requests, lock)
    assert bytes(upstream.output) == bytes(20) + request
    proxy.arm("flip")
    response = sid + struct.pack("!HI", 0, 4) + b"data"
    downstream = MemorySocket()
    proxy._pump_down(MemorySocket(response), downstream, requests, lock)
    return proxy, bytes(downstream.output)


def test_read_payload_is_corrupted_even_with_an_unrelated_sid():
    proxy, response = _exchange(3013, b"\x12\x34")
    assert response[:2] == b"\x12\x34"
    assert response[8:] == b"eata"
    assert proxy._read_replies == 1


def test_oversized_request_is_refused_without_buffering_payload():
    proxy = _KxrPullFaultProxy("unused", 1)
    header = b"\x00\x03" + struct.pack("!H", 3013) + bytes(16)
    header += struct.pack("!I", 16 * 1024 * 1024 + 1)
    requests = {}
    upstream = MemorySocket()
    proxy._pump_up(MemorySocket(bytes(20) + header), upstream,
                   requests, threading.Lock())
    assert bytes(upstream.output) == bytes(20)
    assert requests == {}


def test_metadata_with_read_like_sid_cannot_consume_the_fault():
    proxy, response = _exchange(3017, b"\x00\x03")
    assert response[8:] == b"data"
    assert proxy._read_replies == 0
    assert proxy._mode == "flip"
