"""Observe HAProxy's backend health before exercising a failover transition."""
import csv
from pathlib import Path
import socket

from _test_audit15g_helpers import wait_until
from server_registry import get_server


def backend_states(output):
    rows = csv.DictReader(output.removeprefix("# ").splitlines())
    return {row["svname"]: row["status"] for row in rows
            if row.get("pxname") == "brix_backends"}


def _read_states():
    endpoint = get_server("ha-haproxy")
    path = Path(endpoint.prefix, "logs", "haproxy.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(str(path))
        connection.sendall(b"show stat\n")
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    return backend_states(b"".join(chunks).decode())


def wait_backend_states(expected):
    observed = {}

    def ready():
        observed.clear()
        observed.update(_read_states())
        return all(observed.get(name) == state for name, state in expected.items())

    try:
        wait_until(ready, timeout=10, what=f"HAProxy backend health {expected}")
    except AssertionError as error:
        raise AssertionError(f"{error}; observed {observed}") from error
