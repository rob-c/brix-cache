"""Socket and listener helpers.

These are ``LocalBackend`` internals in spirit (charter §8.4 rule 1):
nothing above the deploy layer should need them directly.  The
listener survey reads ``/proc/net/tcp{,6}`` so a whole-fleet sweep is
one file read, not one probe per instance.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

__all__ = ["tcp_answering", "wait_tcp", "listening_ports", "pids_on_port"]


def tcp_answering(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_tcp(host: str, port: int, deadline: float, poll: float = 0.1) -> float:
    """Block until the port answers; returns elapsed seconds or -1.0 on timeout."""
    start = time.monotonic()
    while True:
        if tcp_answering(host, port):
            return time.monotonic() - start
        elapsed = time.monotonic() - start
        if elapsed >= deadline:
            return -1.0
        time.sleep(poll)


def _proc_net_listen(path: str) -> Set[int]:
    ports: Set[int] = set()
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except OSError:
        return ports
    for line in lines:
        fields = line.split()
        if len(fields) > 3 and fields[3] == "0A":  # TCP_LISTEN
            ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return ports


def listening_ports(candidates: Optional[Iterable[int]] = None) -> Set[int]:
    """LISTEN-state local TCP ports, optionally filtered to ``candidates``."""
    ports = _proc_net_listen("/proc/net/tcp") | _proc_net_listen("/proc/net/tcp6")
    if candidates is not None:
        ports &= set(candidates)
    return ports


def _socket_inodes_on_port(port: int) -> Set[str]:
    inodes: Set[str] = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A":
                if int(fields[1].rsplit(":", 1)[1], 16) == port:
                    inodes.add(fields[9])
    return inodes


def pids_on_port(port: int) -> Set[int]:
    """Pids holding a LISTEN socket on ``port`` (walks /proc/*/fd)."""
    inodes = _socket_inodes_on_port(port)
    if not inodes:
        return set()
    wanted = {"socket:[%s]" % inode for inode in inodes}
    pids: Set[int] = set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            for fd in (proc / "fd").iterdir():
                try:
                    if os.readlink(str(fd)) in wanted:
                        pids.add(int(proc.name))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return pids


def port_holders(ports: Iterable[int]) -> Dict[int, Set[int]]:
    """Map each listening port in ``ports`` to the pids that hold it."""
    return {port: pids_on_port(port) for port in listening_ports(ports)}
