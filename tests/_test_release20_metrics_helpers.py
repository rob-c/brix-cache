"""Scrape/parse helpers shared by the 2.0-readiness metrics labs.

Every axis-(e) lab in docs/10-reference/release-2.0-readiness.md (F6, F10,
F12–F15) reads a ``/metrics`` listener that only its own lifecycle instance
feeds, then asserts on individual samples.  The exposition parser here is the
one thing they all need and none should own: a sample is
``name{label="value",...} number`` and a family's type comes from its
``# TYPE`` line.
"""
from __future__ import annotations

import re
import socket
import time
from typing import Callable, TypeVar

from settings import HOST

_SAMPLE = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)")
_LABEL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')
_TYPE = re.compile(r"^# TYPE (\S+) (\S+)", re.M)

T = TypeVar("T")


def scrape(port: int, path: str = "/metrics", timeout: float = 5.0) -> str:
    """One HTTP/1.1 GET over a raw socket; the body as text."""
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                  .encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200"), head[:80]
    return body.decode(errors="replace")


def samples(body: str) -> list[tuple[str, dict[str, str], float]]:
    """Every ``(name, labels, value)`` sample line of an exposition body."""
    out = []
    for line in body.splitlines():
        if not line or line[0] == "#":
            continue
        m = _SAMPLE.match(line)
        if m is None:
            continue
        labels = dict(_LABEL.findall(m.group(2) or ""))
        try:
            out.append((m.group(1), labels, float(m.group(3))))
        except ValueError:
            continue
    return out


def series(body: str, name: str, **want: str) -> list[tuple[dict[str, str], float]]:
    """The samples of ``name`` whose labels carry every ``want`` pair."""
    return [(labels, v) for n, labels, v in samples(body)
            if n == name and all(labels.get(k) == val for k, val in want.items())]


def value(body: str, name: str, **want: str) -> float | None:
    """The first matching sample's value, or None when the series is absent."""
    rows = series(body, name, **want)
    return rows[0][1] if rows else None


def total(body: str, name: str, **want: str) -> float:
    """Sum over every matching sample (0.0 when none)."""
    return sum(v for _, v in series(body, name, **want))


def type_lines(body: str) -> dict[str, str]:
    """``{family: type}`` from the ``# TYPE`` lines."""
    return dict(_TYPE.findall(body))


def series_keys(body: str) -> set[tuple[str, tuple[tuple[str, str], ...]]]:
    """The identity of every series (name + sorted labels), values dropped."""
    return {(n, tuple(sorted(labels.items()))) for n, labels, _ in samples(body)}


def wait_for(probe: Callable[[], T | None], timeout: float, step: float = 0.25) -> T | None:
    """Poll ``probe`` until it returns a non-None value or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while True:
        got = probe()
        if got is not None:
            return got
        if time.monotonic() >= deadline:
            return None
        time.sleep(step)


def wait_port(port: int, timeout: float = 15.0) -> bool:
    return wait_for(lambda: _connectable(port) or None, timeout, 0.1) is True


def _connectable(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.5):
            return True
    except OSError:
        return False
