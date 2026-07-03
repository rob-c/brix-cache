#!/usr/bin/env python3
"""probe_sink.py — count inbound TCP connections per port.

Used by run_cvmfs_resilience.sh to prove the geo-answer probe guard: a listener
on an ALLOWED CVMFS port (8000) must see connects; a listener on a DISALLOWED
port (2222) must see zero (the guard must never connect to it). Each accepted
connection appends one byte to <statedir>/<port>.hits; the test counts bytes.
"""
import os
import socket
import sys
import threading


def serve(port: int, statedir: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    hits = os.path.join(statedir, f"{port}.hits")
    while True:
        conn, _ = s.accept()
        with open(hits, "ab") as f:
            f.write(b"x")
        conn.close()


def main() -> int:
    statedir = sys.argv[1]
    ports = [int(p) for p in sys.argv[2:]]
    os.makedirs(statedir, exist_ok=True)
    for p in ports:
        threading.Thread(target=serve, args=(p, statedir), daemon=True).start()
    # Signal readiness by touching a marker, then block forever.
    open(os.path.join(statedir, "ready"), "w").close()
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
