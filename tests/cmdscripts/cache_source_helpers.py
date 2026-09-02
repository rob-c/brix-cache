"""Shared process and result helpers for cache-source live checks."""

from __future__ import annotations

import socket
import struct
import time


def _worker_answers(host, port, plane):
    """One readiness probe: True when a WORKER replies on the port — a kXR
    handshake reply for the "root" plane, any response bytes for HTTP."""
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.settimeout(2)
            if plane == "root":
                sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
                need = 16
                while need:
                    chunk = sock.recv(need)
                    if not chunk:
                        return False
                    need -= len(chunk)
                return True
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: ready-probe\r\n\r\n")
            return bool(sock.recv(1))
    except OSError:
        return False


def wait_workers_ready(host, ports, timeout=8.0):
    """Block until a worker answers on every (port, plane) pair.  The master
    binds every listener before the first worker can serve, so a bare TCP
    connect — or the fixed post-start sleep this replaces — proves nothing
    about readiness.  Proceeds on timeout: the scenario's first real operation
    carries the actual diagnostics."""
    deadline = time.monotonic() + timeout
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        pending = [(port, plane) for port, plane in pending
                   if not _worker_answers(host, port, plane)]
        if pending:
            time.sleep(0.05)


def start_servers(nginx_bin, specifications, launcher, stop_server):
    """Start ordered server specifications and return paths plus any failure."""
    started = []
    for name, prefix, config in specifications:
        result = launcher([nginx_bin, "-p", str(prefix), "-c", str(config)])
        if result.returncode != 0:
            stop_servers(started, stop_server)
            output = result.stderr or result.stdout
            return [], (False, f"{name} start failed: {output[-4000:]}")
        started.append(prefix)
    return started, None


def stop_servers(started, stop_server):
    for prefix in reversed(started):
        stop_server(prefix)


def exact_transfer(cat, port, source, destination, expected, client):
    result = cat(port, source, destination, client)
    if result.returncode != 0:
        return False
    return destination.read_bytes() == expected

