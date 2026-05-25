#!/usr/bin/env python3
"""
Mock origin server for write-through isolation testing.

Provides simulated kXR_write responses when real XRootD origin is unavailable.
Used by test_cache_write_through.py for flush scenarios requiring mock behavior.

This module creates a minimal TCP listener that responds to kXR_open followed by
kXR_write requests — simulating successful write-back during close-flush tests.
"""

import socket
import struct
import threading
import time

# XRootD protocol constants from wire.h/opcodes.h
XRD_RESPONSE_HDR_LEN = 8  # 2B streamid + 2B status + 4B dlen
kXR_ok = 0


class MockOriginServer:
    """Simulated XRootD server for write-through flush testing."""

    def __init__(self, port=11099):
        self.port = port
        self.server_socket = None
        self.running = False
        self.requests_received = 0

    def start(self):
        """Start mock origin listener on configured port."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)
        self.running = True

        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()

    def stop(self):
        """Stop mock origin and close all connections."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

    def _handle_client(self, client_sock):
        """Handle single client — respond to kXR_open then accept kXR_write payload."""
        try:
            # Accept kXR_open request (24-byte header + 16-byte body)
            client_sock.recv(24)
            self.requests_received += 1

            # Send kXR_ok response (8-byte header, dlen=0)
            response = struct.pack('<HHI', 0, kXR_ok, 0)
            client_sock.send(response)

            # Accept any subsequent write payload (simulating dirty flush data)
            while self.running:
                try:
                    data = client_sock.recv(1024, socket.MSG_DONTWAIT)
                    if not data:
                        break
                except BlockingIOError:
                    time.sleep(0.01)

        finally:
            client_sock.close()

    def _accept_loop(self):
        """Accept incoming connections and handle each."""
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                thread = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                thread.start()
            except OSError:
                break


def start_mock_origin(port=11099):
    """Start mock origin server for testing. Returns MockOriginServer instance."""
    mock = MockOriginServer(port)
    mock.start()
    return mock
