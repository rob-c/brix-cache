#!/usr/bin/env python3
"""Fault-injecting forward HTTP proxy used by the CVMFS benchmark."""

import argparse
import random
import select
import socket
import sys
import threading
import time


def _arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--mode", choices=["loss", "reorder", "stall", "none"], default="none"
    )
    parser.add_argument("--rate", type=float, default=0.0)
    parser.add_argument("--log", default=None)
    return parser.parse_args()


class _FaultProxy:
    def __init__(self, arguments):
        self.arguments = arguments
        self.log = open(arguments.log, "a") if arguments.log else sys.stderr
        self.stats = {"req": 0, "fault": 0}

    def logline(self, message):
        self.log.write(message + "\n")
        self.log.flush()

    @staticmethod
    def _read_upstream(upstream):
        chunks = []
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    @staticmethod
    def _split_response(data):
        separator = data.find(b"\r\n\r\n")
        if separator < 0:
            return b"", data
        return data[:separator + 4], data[separator + 4:]

    @staticmethod
    def _send_loss(client, head, body):
        cut = len(head) + random.randint(0, max(1, len(body) // 2))
        client.sendall((head + body)[:cut])

    @staticmethod
    def _send_reordered(client, head, body):
        changed = bytearray(body)
        for _index in range(max(1, len(changed) // 64)):
            if changed:
                offset = random.randrange(len(changed))
                changed[offset] ^= 0xFF
        client.sendall(head + bytes(changed))

    @staticmethod
    def _send_stalled(client, head, body):
        client.sendall(head)
        for offset in range(0, len(body), 256):
            client.sendall(body[offset:offset + 256])
            time.sleep(0.05)

    def relay_faulted(self, upstream, client):
        data = self._read_upstream(upstream)
        self.stats["req"] += 1
        clean = self.arguments.mode == "none" or random.random() >= self.arguments.rate
        if clean:
            client.sendall(data)
            return
        self.stats["fault"] += 1
        head, body = self._split_response(data)
        handlers = {
            "loss": self._send_loss,
            "reorder": self._send_reordered,
            "stall": self._send_stalled,
        }
        handlers[self.arguments.mode](client, head, body)

    @staticmethod
    def _drain_headers(stream):
        while True:
            header = stream.readline()
            if header in (b"\r\n", b"\n", b""):
                return

    def _read_request(self, client):
        stream = client.makefile("rb")
        line = stream.readline().decode("latin1").strip()
        if not line:
            return None
        fields = line.split()
        self._drain_headers(stream)
        return fields[0], fields[1]

    def _handle_get(self, client, target):
        if not target.startswith("http://"):
            return
        rest = target[7:]
        hostport, _separator, path = rest.partition("/")
        host, _separator, port_text = hostport.partition(":")
        port = int(port_text) if port_text else 80
        upstream = socket.create_connection((host, port), 10)
        try:
            request = (
                "GET /%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
                % (path, hostport)
            )
            upstream.sendall(request.encode())
            self.relay_faulted(upstream, client)
        finally:
            upstream.close()

    @staticmethod
    def _tunnel_once(client, upstream):
        ready, _write, _error = select.select([client, upstream], [], [], 30)
        if not ready:
            return False
        for source in ready:
            data = source.recv(65536)
            if not data:
                return False
            destination = upstream if source is client else client
            destination.sendall(data)
        return True

    def _handle_connect(self, client, target):
        host, port_text = target.split(":")
        upstream = socket.create_connection((host, int(port_text)), 10)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            while self._tunnel_once(client, upstream):
                pass
        finally:
            upstream.close()

    def handle(self, client):
        try:
            request = self._read_request(client)
            if request is None:
                return
            method, target = request
            handlers = {"GET": self._handle_get, "CONNECT": self._handle_connect}
            handler = handlers.get(method)
            if handler is not None:
                handler(client, target)
        except OSError:
            pass
        finally:
            client.close()

    def _report_stats(self):
        while True:
            time.sleep(3)
            self.logline(
                "STATS req=%d fault=%d"
                % (self.stats["req"], self.stats["fault"])
            )

    def run(self):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.arguments.port))  # net-literal-allow: standalone fault proxy binds loopback by design
        listener.listen(128)
        self.logline(
            "failproxy mode=%s rate=%.2f port=%d"
            % (self.arguments.mode, self.arguments.rate, self.arguments.port)
        )
        threading.Thread(target=self._report_stats, daemon=True).start()
        while True:
            client, _address = listener.accept()
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()


def main():
    _FaultProxy(_arguments()).run()


if __name__ == "__main__":
    main()
