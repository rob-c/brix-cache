"""One backend-neutral UDP service test for process and Minikube runs."""

import socket
import sys

from brixtest import binary, case, endpoint, probe, server


_SCRIPT = (
    "import socket, sys\n"
    "server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "server.bind((sys.argv[1], int(sys.argv[2])))\n"
    "while True:\n"
    "    payload, peer = server.recvfrom(65507)\n"
    "    server.sendto(payload, peer)\n"
)
_PYTHON_IMAGE = (
    "python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a"
)
PYTHON = binary(
    "udp_python", path=sys.executable, image=_PYTHON_IMAGE,
    image_path="/usr/local/bin/python3",
)
UDP_ECHO = server(
    "udp_echo", command=(PYTHON, "-c", _SCRIPT, "{host}", "{port}"),
    endpoints=(endpoint("echo", protocol="udp"),),
    probe=probe("none", timeout=30),
)


@case(UDP_ECHO, PYTHON, backend="auto", timeout=60, keep="never")
def test_same_udp_declaration_runs_locally_and_in_minikube(run):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(10)
    client.sendto(b"brixtest-udp\x00\xff", run.server(UDP_ECHO).address("echo"))
    assert client.recv(4096) == b"brixtest-udp\x00\xff"
